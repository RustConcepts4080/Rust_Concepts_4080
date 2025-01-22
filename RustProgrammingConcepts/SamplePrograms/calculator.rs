use std::io;

fn main() {
    println!("Welcome to the Rust Calculator!");

    // Prompt the user to select an operation
    println!("Please choose an operation: +, -, *, /");
    let mut operation = String::new();
    io::stdin()
        .read_line(&mut operation)
        .expect("Failed to read input");
    let operation = operation.trim(); // Remove whitespace

    // Prompt the user for the first number
    println!("Enter the first number:");
    let mut first_input = String::new();
    io::stdin()
        .read_line(&mut first_input)
        .expect("Failed to read input");
    let num1: f64 = match first_input.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            println!("Invalid number. Exiting.");
            return;
        }
    };

    // Prompt the user for the second number
    println!("Enter the second number:");
    let mut second_input = String::new();
    io::stdin()
        .read_line(&mut second_input)
        .expect("Failed to read input");
    let num2: f64 = match second_input.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            println!("Invalid number. Exiting.");
            return;
        }
    };

    // Perform the calculation based on the operation
    let result = match operation {
        "+" => num1 + num2,
        "-" => num1 - num2,
        "*" => num1 * num2,
        "/" => {
            if num2 == 0.0 {
                println!("Error: Division by zero is not allowed.");
                return;
            }
            num1 / num2
        }
        _ => {
            println!("Invalid operation. Please use +, -, *, or /.");
            return;
        }
    };

    // Print the result
    println!("The result of {} {} {} = {}", num1, operation, num2, result);
}

