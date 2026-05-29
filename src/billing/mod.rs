pub mod backend;
pub mod types;

pub use backend::*;
pub use types::*;

use anyhow::Result;

pub struct BillingManager<T: BillingBackend> {
    backend: T,
}

impl<T: BillingBackend> BillingManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub async fn create_plan(&self, plan: &BillingPlan) -> Result<()> {
        if plan.name.is_empty() {
            anyhow::bail!("plan name cannot be empty");
        }
        if plan.price_monthly == 0 {
            anyhow::bail!("monthly price must be > 0");
        }
        self.backend.create_plan(plan).await
    }

    pub async fn list_plans(&self) -> Result<Vec<BillingPlan>> {
        self.backend.list_plans().await
    }

    pub async fn generate_invoice(&self, invoice: &Invoice) -> Result<()> {
        if invoice.username.is_empty() {
            anyhow::bail!("invoice username cannot be empty");
        }
        if invoice.amount == 0 {
            anyhow::bail!("invoice amount must be > 0");
        }
        self.backend.generate_invoice(invoice).await
    }

    pub async fn list_invoices(&self, username: &str) -> Result<Vec<Invoice>> {
        if username.is_empty() {
            anyhow::bail!("username cannot be empty");
        }
        self.backend.list_invoices(username).await
    }

    pub async fn mark_invoice_paid(&self, invoice_id: &str) -> Result<()> {
        if invoice_id.is_empty() {
            anyhow::bail!("invoice ID cannot be empty");
        }
        self.backend.mark_invoice_paid(invoice_id).await
    }

    pub async fn get_billing_summary(&self) -> Result<BillingSummary> {
        self.backend.get_billing_summary().await
    }
}
