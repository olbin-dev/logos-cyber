use crate::engine::parse::HttpRequest;
use std::collections::HashMap;

/// Expand payload combinations into variable maps for each attack iteration.
/// Unsupported file refs become a single placeholder warning via empty expansion skip.
pub fn expand_payload_iterations(
    req: &HttpRequest,
) -> Result<Vec<HashMap<String, String>>, String> {
    if req.payloads.is_empty() {
        return Ok(vec![HashMap::new()]);
    }

    let mut keys: Vec<String> = req.payloads.keys().cloned().collect();
    keys.sort();

    let mut lists: Vec<Vec<String>> = Vec::new();
    for k in &keys {
        let vals = req.payloads.get(k).cloned().unwrap_or_default();
        let filtered: Vec<String> = vals
            .into_iter()
            .filter(|v| !v.starts_with("__FILE_REF__:"))
            .collect();
        if filtered.is_empty() {
            // No inline payloads usable
            return Ok(vec![HashMap::new()]);
        }
        lists.push(filtered);
    }

    let attack = req
        .attack
        .as_deref()
        .unwrap_or("batteringram")
        .to_lowercase();

    let combos = match attack.as_str() {
        "clusterbomb" => clusterbomb(&lists),
        "pitchfork" => pitchfork(&lists),
        _ => batteringram(&lists),
    };

    let mut out = Vec::new();
    for combo in combos {
        let mut map = HashMap::new();
        for (i, k) in keys.iter().enumerate() {
            if let Some(v) = combo.get(i) {
                map.insert(k.clone(), v.clone());
            }
        }
        out.push(map);
    }
    // Safety cap to avoid runaway fuzz in desktop app
    const MAX: usize = 256;
    if out.len() > MAX {
        out.truncate(MAX);
    }
    Ok(out)
}

fn batteringram(lists: &[Vec<String>]) -> Vec<Vec<String>> {
    // All payload sets share the same positions — zip by index using first list length,
    // repeating shorter lists' last? Nuclei batteringram: one payload set replaces all positions.
    // When multiple keys: typically one list applied. We zip min length.
    if lists.is_empty() {
        return vec![vec![]];
    }
    if lists.len() == 1 {
        return lists[0].iter().map(|v| vec![v.clone()]).collect();
    }
    pitchfork(lists)
}

fn pitchfork(lists: &[Vec<String>]) -> Vec<Vec<String>> {
    if lists.is_empty() {
        return vec![vec![]];
    }
    let n = lists.iter().map(|l| l.len()).min().unwrap_or(0);
    let mut out = Vec::new();
    for i in 0..n {
        let row: Vec<String> = lists.iter().map(|l| l[i].clone()).collect();
        out.push(row);
    }
    out
}

fn clusterbomb(lists: &[Vec<String>]) -> Vec<Vec<String>> {
    fn rec(lists: &[Vec<String>], idx: usize, cur: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        if idx == lists.len() {
            out.push(cur.clone());
            return;
        }
        for v in &lists[idx] {
            cur.push(v.clone());
            rec(lists, idx + 1, cur, out);
            cur.pop();
            if out.len() >= 256 {
                return;
            }
        }
    }
    let mut out = Vec::new();
    let mut cur = Vec::new();
    rec(lists, 0, &mut cur, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clusterbomb_two() {
        let mut req = HttpRequest {
            method: "GET".into(),
            path: vec![],
            headers: HashMap::new(),
            body: None,
            raw: vec![],
            matchers_condition: "or".into(),
            matchers: vec![],
            extractors: vec![],
            redirects: false,
            max_redirects: 0,
            stop_at_first_match: false,
            payloads: HashMap::from([
                ("a".into(), vec!["1".into(), "2".into()]),
                ("b".into(), vec!["x".into(), "y".into()]),
            ]),
            attack: Some("clusterbomb".into()),
            cookie_reuse: true,
        };
        let it = expand_payload_iterations(&req).unwrap();
        assert_eq!(it.len(), 4);
        let _ = &mut req;
    }
}
