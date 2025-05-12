# Implementation of  Bolt4

This is a **practice implementation** of the BOLT-4 Onion Routing Protocol from the Lightning Network, written in Rust. It’s intended for educational purposes and experimentation, not production use.

## Features

- Parses onion routing data as per BOLT-4
- Extracts and writes onion hex packets to a file

## Usage

Build and run with:

```bash
cargo run --release -- "$output_directory" "$input_file"
```

This reads the input file, parses the onion packet, and writes the hex output to `output.txt` in the specified directory.


## Note

This project is **for practice and learning only**.  
See [BOLT-4 spec](https://github.com/lightning/bolts/blob/master/04-onion-routing.md) for protocol details.


