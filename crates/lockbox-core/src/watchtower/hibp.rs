//! Have I Been Pwned range API client (Task 15).

use super::Finding;
use crate::model::Item;
use crate::Result;

pub struct Hibp;

pub fn breached(_items: &[Item], _hibp: &Hibp) -> Result<Vec<Finding>> {
    unimplemented!("Task 15")
}
