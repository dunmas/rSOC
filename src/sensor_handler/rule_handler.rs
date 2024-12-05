use std::borrow::Borrow;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};

pub fn get_rules_map(rules_file: &String) -> HashMap<String, (String, (String, String))> {
    let mut file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .read(true)
                        .open(&rules_file)
                        .unwrap();
    let buf: &mut String = &mut "".to_owned();
    let mut result: HashMap<String, (String, (String, String))> = HashMap::new();

    match (file).read_to_string(buf){
        Ok(_) => {
            let strings = buf.split("\n");
            let mut temp_hashmap: HashMap<String, String> = HashMap::new();

            for string in strings {
                // level[:1:]net[:2:]hash[:1:]252fe[:2:]name[:1:]beb[:2:]description[:1:]ra[:2:]other_parameters...
                let high_level_parsed_rule: Vec<&str> = string.split("[:2:]").collect();

                for parameter in high_level_parsed_rule {
                    let param_pair: Vec<&str> = parameter.split("[:1:]").collect();
                    temp_hashmap.insert(param_pair[0].to_string(), param_pair[1].to_string());
                }
            }

            let level = temp_hashmap["level"].to_string();
            let hash = temp_hashmap["hash"].to_string();
            
            for param in temp_hashmap {
                if param.0 == "level" || param.0 == "hash" { continue; }
                result.insert(level.to_string(), (hash.to_string(), (param.0, param.1)));
            }
        },
        Err(e) => println!("Error occured while reading from audit file: {}", e)
    }

    result
}

pub fn get_rules_list(rule_type: &str, rules_file: &String) {
    
}

pub fn add_rule(rule_level: &str, rule_name: &str, rule_description: &str, rule_fields: &HashMap<&str, &str>, rules_file: &str) {

}

pub fn delete_rule(rule_level: &String, rule_hash: &String, rules_file: &String) {

}