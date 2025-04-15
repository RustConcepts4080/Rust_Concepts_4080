use std::fs::{File, OpenOptions, remove_file};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;
use rand::rngs::OsRng;
use rand::RngCore;

fn shred_file<P: AsRef<Path>>(path: P, passes: u8) -> io::Result<()> {
    let path = path.as_ref();

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;

    let file_len = file.metadata()?.len();

    for _ in 0..passes {
        file.seek(SeekFrom::Start(0)?);
        let mut buffer = vec![0u8; 1024 * 1024];

        let mut bytes_remaining = file_len;
        while bytes_remaining > 0 {
            let write_size = std::cmp::min(buffer.len() as u64, bytes_remaining) as usize;

            OsRng.fill_bytes(&mut buffer[..write_size]);
            file.write_all(&buffer[..write_size])?;

            bytes_remaining -= write_size as u64;
        }

        file.flush()?;
    }

    file.sync_all()?;
    drop(file);

    remove_file(path)?;

    Ok(())
}