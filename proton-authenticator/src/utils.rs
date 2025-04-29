use std::collections::HashMap;
use std::hash::Hash;

pub fn list_to_map<T, K: Eq + Hash, F: Fn(&T) -> K>(input: Vec<T>, f: F) -> HashMap<K, T> {
    let mut map = HashMap::new();
    for item in input {
        let key = f(&item);
        map.insert(key, item);
    }
    map
}
