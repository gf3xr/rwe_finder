use {
    std::{
        fs,
        path::Path,
    },
    pelite::PeFile,
    walkdir::WalkDir,
};

// USE, rwe_finder.exe C:\etc etc
// Recursively finds RWE sections on dlls

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("usage {} directory_path", args[0]);
    } else {
        let directory_path = Path::new(&args[1]);
        scan_directory(directory_path);
        println!("scan finished");
    }
}

fn is_rwe_characteristics(characteristics: u32) -> bool {
    const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;

    (characteristics & IMAGE_SCN_MEM_READ != 0) &&
    (characteristics & IMAGE_SCN_MEM_WRITE != 0) &&
    (characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
}

fn scan_directory(directory_path: &Path) {
    println!("searching");

    for entry in WalkDir::new(directory_path).into_iter().filter_map(|e| e.ok()) {
        if entry.path().extension().map_or(false, |ext| ext == "dll") {
            let file_path = entry.path();
            match find_rwe_sections(file_path) {
                sections if !sections.is_empty() => {
                    println!("\x1b[1;32m Found rwx sections in {}\x1b[0m", file_path.display());
                    for (section, size) in sections {
                        println!("Section: {}, Size: {} bytes", section, size);
                    }
                    println!();
                }
                _ => {}
            }
        }
    }
}

fn find_rwe_sections(file_path: &Path) -> Vec<(String, u32)> {
    let mut rwe_sections = Vec::new();

    if let Ok(buffer) = fs::read(file_path) {
        if let Ok(pe) = PeFile::from_bytes(&buffer) {
            for section in pe.section_headers() {
                if is_rwe_characteristics(section.Characteristics) {
                    let name = String::from_utf8_lossy(&section.Name).trim_end_matches('\0').to_string();
                    rwe_sections.push((name, section.VirtualSize));
                }
            }
        }
    }

    rwe_sections
}