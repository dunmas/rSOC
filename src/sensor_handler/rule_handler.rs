use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::mem;
use regex::Regex;
use sha2::{Sha256, Digest};
use std::io::Seek;

use crate::structs::soc_structs::multithread::FileMutexes;

pub fn get_rules_list(rule_type: &str, file_mutexes: &FileMutexes) {
    if let Some(rules_vec_by_level) =  get_rules_map(file_mutexes).get(rule_type) {
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

pub fn add_rule(rule_level: String, rule_name: String, rule_payload: String, rule_fields: &HashMap<String, String>, rules_file: &String, file_mutexes: &FileMutexes) -> bool {
    let mut locked_rules_file = file_mutexes.rules_mutex.lock().unwrap();

    let hashing_str = rule_name.to_string() + rule_payload.as_str();
    let mut hasher = Sha256::new();
    hasher.update(hashing_str);
    let raw_hash = hasher.finalize();
    let hash = format!("{:.5}", format!("{:x}", raw_hash));
    let mut param_vec: Vec<String> = Vec::new();

    param_vec.push("level".to_string() + "[:1:]" + &rule_level);
    param_vec.push("hash".to_string() + "[:1:]" + &hash);
    param_vec.push("name".to_string() + "[:1:]" + &rule_name);
    param_vec.push("payload".to_string() + "[:1:]" + &rule_payload);
    
    for opt_pair in rule_fields {
        let joined_string = opt_pair.0.to_string() + "[:1:]" + opt_pair.1;
        param_vec.push(joined_string);
    }

    let result = match writeln!(locked_rules_file, "{}", param_vec.join("[:2:]")) {
        Ok(_) => true,
        Err(_e) => false
    };

    if result {
        let _ = mem::replace(&mut *locked_rules_file,
        OpenOptions::new()
        .append(true)
        .create(true)
        .read(true)
        .open(&rules_file)
        .unwrap());
    }

    result
}

pub fn delete_rule(rule_level: &String, rule_hash: &String, rules_file: &String, file_mutexes: &FileMutexes) {
    let pattern_str = format!(r"level\[:1:\]{}\[:2:\]hash\[:1:\]{}\[:2:\]", rule_level, rule_hash);
    let pattern = Regex::new(&pattern_str).unwrap();
    let lines: Vec<String>;
    let mut locked_file = file_mutexes.rules_mutex.lock().unwrap();
    let buf: &mut String = &mut "".to_owned();

    match locked_file.read_to_string(buf) {
        Ok(_) => {
            if let Some(_) = pattern.find(&buf) {
                lines = buf.lines()
                .filter(|line| !pattern.is_match(line))
                .map(String::from)
                .collect();
            }
            else {
                println!("There is no rule with these level and hash parameters.");
                return;
            }
        },
        Err(_e) => { println!("Error while parcing rules file."); return; }
    }

    if lines.len() > 0 {
        let _ = mem::replace(&mut *locked_file,
            OpenOptions::new()
            .truncate(true)
            .write(true)
            .read(true)
            .open(&rules_file)
            .unwrap());
    }
    
    let result = match writeln!(locked_file, "{}", lines.join("\n")) {
        Ok(_) => true,
        Err(_e) => false
    };

    if result {
        let _ = mem::replace(&mut *locked_file,
        OpenOptions::new()
        .append(true)
        .create(true)
        .read(true)
        .open(&rules_file)
        .unwrap());
    }

    println!("Rule deleted successfully.");
}

pub fn get_rules_map(file_mutexes: &FileMutexes) -> HashMap<String, Vec<HashMap<String, Vec<(String, String)>>>> {
    let mut file = file_mutexes.rules_mutex.lock().unwrap();
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

            let _ = file.rewind();
            return result;
        },
        Err(e) => println!("Error occured while reading from audit file: {}", e)
    }

    let _ = file.rewind();
    result
}