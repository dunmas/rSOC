use std::borrow::Borrow;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};

fn get_rules_map(rules_file: &String) -> HashMap<String, Vec<HashMap<String, Vec<(String, String)>>>> {
    let mut file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .read(true)
                        .open(&rules_file)
                        .unwrap();
    let buf: &mut String = &mut "".to_owned();
    let mut result: HashMap<String, Vec<HashMap<String, Vec<(String, String)>>>> = HashMap::new();

    match (file).read_to_string(buf){
        Ok(_) => {
            let strings = buf.split("\n");
            result.insert("net".to_string(), Vec::new());
            result.insert("host".to_string(), Vec::new());

            for string in strings {
                let mut temp_hashmap: HashMap<String, String> = HashMap::new();
                // level[:1:]net[:2:]hash[:1:]252fe[:2:]name[:1:]beb[:2:]description[:1:]ra[:2:]other_parameters...
                let high_level_parsed_rule: Vec<&str> = string.split("[:2:]").collect();

                for parameter in high_level_parsed_rule {
                    let param_pair: Vec<&str> = parameter.split("[:1:]").collect();
                    temp_hashmap.insert(param_pair[0].to_string(), param_pair[1].to_string());
                }

                let level = temp_hashmap["level"].to_string();
                let hash = temp_hashmap["hash"].to_string();
                let mut temp_vec: Vec<(String, String)> = Vec::new();

                for param in temp_hashmap {
                    if param.0 == "level" || param.0 == "hash" { continue; }
                    temp_vec.push((param.0, param.1));
                }

                if let Some(result_empty_rules_vector) = result.get_mut(&level.to_string()) {
                    let m: HashMap<String, Vec<(String, String)>> = vec![(hash, temp_vec)].into_iter().collect();
                    result_empty_rules_vector.push(m);
                }
            }
        },
        Err(e) => println!("Error occured while reading from audit file: {}", e)
    }

    result
}

pub fn get_rules_list(rule_type: &str, rules_file: &String) {
    if let Some(rules_vec_by_level) =  get_rules_map(rules_file).get(rule_type) {
        for level_rule in rules_vec_by_level {
            let rule_hash_vec: Vec<String> = level_rule.clone().into_keys().collect();
            let rule_hash: &String = rule_hash_vec.first().unwrap();
            println!("------------------------------------------------------------------------------------------\n\
                      Rule level: {}\n\
                      Rule hash: {}\n", rule_type, rule_hash);

            for param in level_rule.get(rule_hash).unwrap() {
                println!("{}: {}", param.0, param.1);
            }
        }
    }
}

pub fn add_rule(rule_level: &str, rule_name: &str, rule_payload: &str, rule_fields: &HashMap<&str, &str>, rules_file: &str) {

}

pub fn delete_rule(rule_level: &String, rule_hash: &String, rules_file: &String) {

}