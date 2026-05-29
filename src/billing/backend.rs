use super::types::*;
use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[async_trait]
pub trait BillingBackend: Send + Sync {
    async fn create_plan(&self, plan: &BillingPlan) -> Result<()>;
    async fn list_plans(&self) -> Result<Vec<BillingPlan>>;
    async fn get_plan(&self, name: &str) -> Result<BillingPlan>;
    async fn generate_invoice(&self, invoice: &Invoice) -> Result<()>;
    async fn list_invoices(&self, username: &str) -> Result<Vec<Invoice>>;
    async fn mark_invoice_paid(&self, invoice_id: &str) -> Result<()>;
    async fn get_billing_summary(&self) -> Result<BillingSummary>;
    async fn record_usage(&self, record: &UsageRecord) -> Result<()>;
}

#[derive(Clone, Default)]
pub struct MockBillingBackend {
    plans: Arc<RwLock<HashMap<String, BillingPlan>>>,
    invoices: Arc<RwLock<Vec<Invoice>>>,
}

impl MockBillingBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BillingBackend for MockBillingBackend {
    async fn create_plan(&self, plan: &BillingPlan) -> Result<()> {
        let mut plans = self.plans.write().expect("lock poisoned");
        if plans.contains_key(&plan.name) {
            bail!("billing plan '{}' already exists", plan.name);
        }
        plans.insert(plan.name.clone(), plan.clone());
        Ok(())
    }

    async fn list_plans(&self) -> Result<Vec<BillingPlan>> {
        let plans = self.plans.read().expect("lock poisoned");
        Ok(plans.values().cloned().collect())
    }

    async fn get_plan(&self, name: &str) -> Result<BillingPlan> {
        let plans = self.plans.read().expect("lock poisoned");
        plans
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("plan '{name}' not found"))
    }

    async fn generate_invoice(&self, invoice: &Invoice) -> Result<()> {
        let mut invoices = self.invoices.write().expect("lock poisoned");
        if invoices.iter().any(|i| i.id == invoice.id) {
            bail!("invoice '{}' already exists", invoice.id);
        }
        invoices.push(invoice.clone());
        Ok(())
    }

    async fn list_invoices(&self, username: &str) -> Result<Vec<Invoice>> {
        let invoices = self.invoices.read().expect("lock poisoned");
        Ok(invoices
            .iter()
            .filter(|i| i.username == username)
            .cloned()
            .collect())
    }

    async fn mark_invoice_paid(&self, invoice_id: &str) -> Result<()> {
        let mut invoices = self.invoices.write().expect("lock poisoned");
        let invoice = invoices
            .iter_mut()
            .find(|i| i.id == invoice_id)
            .ok_or_else(|| anyhow::anyhow!("invoice '{invoice_id}' not found"))?;
        invoice.status = InvoiceStatus::Paid;
        invoice.paid_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        Ok(())
    }

    async fn get_billing_summary(&self) -> Result<BillingSummary> {
        let invoices = self.invoices.read().expect("lock poisoned");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let month_ago = now - 30 * 86400;
        let mut total = 0u64;
        let mut pending = 0;
        let mut overdue = 0;
        let mut paid_month = 0u64;
        for inv in invoices.iter() {
            match inv.status {
                InvoiceStatus::Pending | InvoiceStatus::Overdue => {
                    total += inv.amount;
                    pending += 1;
                    if inv.due_at < now {
                        overdue += 1;
                    }
                }
                InvoiceStatus::Paid => {
                    if inv.issued_at > month_ago {
                        paid_month += inv.amount;
                    }
                }
                InvoiceStatus::Cancelled => {}
            }
        }
        Ok(BillingSummary {
            total_outstanding: total,
            pending_count: pending,
            overdue_count: overdue,
            paid_this_month: paid_month,
        })
    }

    async fn record_usage(&self, _record: &UsageRecord) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_list_plan() {
        let backend = MockBillingBackend::new();
        let plan = BillingPlan {
            name: "Silver".into(),
            price_monthly: 150_000,
            price_setup: 50_000,
            currency: "IDR".into(),
            grace_days: 7,
            enabled: true,
        };
        backend.create_plan(&plan).await.unwrap();
        let plans = backend.list_plans().await.unwrap();
        assert_eq!(plans.len(), 1);
    }

    #[tokio::test]
    async fn test_generate_list_invoice() {
        let backend = MockBillingBackend::new();
        let inv = Invoice {
            id: "INV-001".into(),
            username: "user1".into(),
            amount: 150_000,
            currency: "IDR".into(),
            issued_at: 1_000_000,
            due_at: 1_700_000,
            paid_at: None,
            status: InvoiceStatus::Pending,
            items: vec![],
        };
        backend.generate_invoice(&inv).await.unwrap();
        let invoices = backend.list_invoices("user1").await.unwrap();
        assert_eq!(invoices.len(), 1);
    }
}
