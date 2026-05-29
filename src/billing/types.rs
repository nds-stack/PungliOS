use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BillingPlan {
    pub name: String,
    pub price_monthly: u64,
    pub price_setup: u64,
    pub currency: String,
    pub grace_days: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Invoice {
    pub id: String,
    pub username: String,
    pub amount: u64,
    pub currency: String,
    pub issued_at: u64,
    pub due_at: u64,
    pub paid_at: Option<u64>,
    pub status: InvoiceStatus,
    pub items: Vec<InvoiceItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InvoiceStatus {
    Pending,
    Paid,
    Overdue,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvoiceItem {
    pub description: String,
    pub amount: u64,
    pub quantity: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageRecord {
    pub username: String,
    pub period_start: u64,
    pub period_end: u64,
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub session_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BillingSummary {
    pub total_outstanding: u64,
    pub pending_count: usize,
    pub overdue_count: usize,
    pub paid_this_month: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_billing_plan_creation() {
        let plan = BillingPlan {
            name: "Silver 10Mbps".into(),
            price_monthly: 150_000,
            price_setup: 50_000,
            currency: "IDR".into(),
            grace_days: 7,
            enabled: true,
        };
        assert_eq!(plan.price_monthly, 150_000);
    }

    #[test]
    fn test_invoice_status() {
        assert_eq!(format!("{:?}", InvoiceStatus::Paid), "Paid");
        assert_eq!(format!("{:?}", InvoiceStatus::Pending), "Pending");
    }
}
