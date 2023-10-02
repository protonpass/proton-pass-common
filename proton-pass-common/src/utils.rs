use rand::{thread_rng, Rng};

pub fn get_random_index<T>(vector: &[T]) -> Option<usize> {
    if vector.is_empty() {
        None
    } else {
        Some(thread_rng().gen_range(0..vector.len()))
    }
}

pub fn uppercase_first_letter(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}
