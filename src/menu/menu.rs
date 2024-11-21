    use std::io::{self, Write};
    const MAIN_MENU: &str = "\
        ------------------------------------------------------\n\
        Hello! This is rSOC Management Server command console.\n\
        ------------------------------------------------------\n\
        Please, select option:\n\
        1) Event log               4) Users settings\n\
        2) Sensors settings        5) Exit\n\
        3) Audit settings\n\
        ------------------------------------------------------";
    const EVENT_MENU: &str = "\
            ------------------------------------------------------\n\
            Select option:\n\
            1) Check overall events (10 latest)\n\
            2) Check sensor events (10 latest)\n\
            3) Back\n\
            ------------------------------------------------------";
    const SENSORS_MENU: &str = "Select option:\n \
            1) List of sensors\n \
            2) Start/stop sensor\n \
            3) Update rules\n \
            4) Back\n";
    const USERS_MENU: &str = "Select option:\n \
            1) List of users\n \
            2) Update user\n \
            3) Delete user\n \
            4) Back\n";
    const AUDIT_MENU: &str = "Select option:\n \
            1) Start/stop system audit\n \
            2) Check audit log (10 latest)\n \
            3) Back\n";

    macro_rules! pause {
        () => {
            {
                println!("\
                ------------------------------------------------------\n\
                Press enter to continue...");
                let mut buffer = String::new();
                
                std::io::stdin()
                    .read_line(&mut buffer)
                    .expect("Failed to read line");
            }
        };
    }

    pub fn main_menu() {
        loop {
            println!("{}", MAIN_MENU);
            let choise = get_user_choice();

            match choise.as_str() {
                "1" => event_menu(),
                "2" => println!("Foo"),
                "3" => println!("Foo"),
                "4" => println!("Foo"),
                "5" => {
                    println!("Goodbye.");
                    break;
                },
                _ => println!("Undefined option. Try again.\n"),
            }
        }
    }
    
    fn get_user_choice() -> String {
        let mut choice = String::new();
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut choice).expect("Input error.");
        choice.trim().to_string()
    }



    fn event_menu() {
        loop {
            println!("{}", EVENT_MENU);
            let choise = get_user_choice();

            match choise.as_str() {
                "1" => {
                    println!("overall");
                    pause!();
                },
                "2" => {
                    println!("sensor");
                    pause!();
                },
                "3" => break,
                _ => println!("Undefined option. Try again."),
            }
        }
    }

    fn sensors_menu() {

    }

    fn users_menu() {

    }

    fn audit_menu() {

    }