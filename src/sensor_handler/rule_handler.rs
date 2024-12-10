use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, Write};
use std::hash::Hash;
use clap::builder::Str;
use regex::Regex;
use sha2::{Sha256, Digest};

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

pub fn add_rule(rule_level: String, rule_name: String, rule_payload: String, rule_fields: &HashMap<String, String>, rules_file: &String) -> bool {
    let mut rules_file = OpenOptions::new()
                            .append(true)
                            .create(true)
                            .read(true)
                            .open(rules_file)
                            .unwrap();

    let hashing_str = rule_name.to_string() + rule_payload.as_str();
    let mut hasher = Sha256::new();
    hasher.update(hashing_str);
    let raw_hash = hasher.finalize();
    let hash = format!("{:.5}", format!("{:x}", raw_hash));

    // let _level = "level".to_string();
    // let _hash = "hash".to_string();
    // let _name = "name".to_string();
    // let _payload = "payload".to_string();

    // let mut param_pairs: HashMap<&String, &String> = vec![
    //     (&_level, &rule_level),
    //     (&_hash, &hash),
    //     (&_name, &rule_name),
    //     (&_payload, &rule_payload)
    // ].into_iter().collect();

    // param_pairs.extend(rule_fields);
    let mut param_vec: Vec<String> = Vec::new();

    param_vec.push("level".to_string() + "[:1:]" + &rule_level);
    param_vec.push("hash".to_string() + "[:1:]" + &hash);
    param_vec.push("name".to_string() + "[:1:]" + &rule_name);
    param_vec.push("payload".to_string() + "[:1:]" + &rule_payload);
    
    for opt_pair in rule_fields {
        let joined_string = opt_pair.0.to_string() + "[:1:]" + opt_pair.1;
        param_vec.push(joined_string);
    }

    let result = match writeln!(rules_file, "{}", param_vec.join("[:2:]")) {
        Ok(_) => true,
        Err(_e) => false
    };

    result
}

pub fn delete_rule(rule_level: &String, rule_hash: &String, rules_file: &String) {
    let pattern_str = format!(r"level\[:1:\]{}\[:2:\]hash\[:1:\]{}\[:2:\]", rule_level, rule_hash);
    let pattern = Regex::new(&pattern_str).unwrap();
    let mut lines: Vec<String> = Vec::new();

    match fs::read_to_string(rules_file) {
        Ok(file) => {
            lines = file.lines()
            .filter(|line| !pattern.is_match(line))
            .map(String::from)
            .collect();
        },
        Err(_e) => { println!("Error while parcing rules file."); return; }
    }

    let mut n_file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&rules_file)
                        .unwrap();
    
    for line in lines {
        let _ = match writeln!(n_file, "{}", line) {
            Ok(_) => {},
            Err(_e) => {  println!("Error while writing file back."); }
        };
    }    

    println!("Rule deleted successfully.");
}

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
                if string == "" { continue; }
                
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

            return result;
        },
        Err(e) => println!("Error occured while reading from audit file: {}", e)
    }

    result
}