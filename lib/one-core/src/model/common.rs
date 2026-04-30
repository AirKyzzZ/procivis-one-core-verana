#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Clone, Debug)]
pub struct GetListResponse<ResponseItem> {
    pub values: Vec<ResponseItem>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[cfg(test)]
impl<ResponseItem> GetListResponse<ResponseItem> {
    pub fn empty() -> Self {
        Self {
            values: vec![],
            total_pages: 0,
            total_items: 0,
        }
    }

    pub fn one(value: ResponseItem) -> Self {
        Self {
            values: vec![value],
            total_pages: 1,
            total_items: 1,
        }
    }

    pub fn one_page_of(values: Vec<ResponseItem>) -> Self {
        let total_items = values.len() as u64;
        Self {
            values,
            total_pages: 1,
            total_items,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockType {
    /// Exclusive lock
    Update,
    /// Shared lock
    Share,
}
