use std::collections::HashMap;
use std::hash::Hash;

const LINE_START_MAX_LEN: usize = 20;

pub fn list_to_map<T, K: Eq + Hash, F: Fn(&T) -> K>(input: Vec<T>, f: F) -> HashMap<K, T> {
    let mut map = HashMap::new();
    for item in input {
        let key = f(&item);
        map.insert(key, item);
    }
    map
}

pub fn conceal(input: &str) -> String {
    let suffix = if input.len() > LINE_START_MAX_LEN { "..." } else { "" }.to_string();
    format!(
        "{}{}",
        input.chars().take(LINE_START_MAX_LEN).collect::<String>(),
        suffix
    )
}
