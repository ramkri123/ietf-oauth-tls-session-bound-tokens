#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import argparse
from pathlib import Path

# --- Configuration (User can edit these) ---
VERSION = ""    # Set explicitly (e.g., "00") to target a version, or leave empty "" for latest.
SOURCE = ""     # Master file (e.g. "draft-mw-spice.md"). If empty, uses [prefix].md.
AUTO_BUMP = False # Set to True to automatically increment the version on every run.
PUSH = True      # Set to False to commit locally only by default.
CLEANUP = True   # Set to True to remove redundant versioned source (.md) and old versions.
# ---------------------------------------------

def get_latest_version(prefix):
    """Finds the latest version number for files starting with the prefix."""
    # Look for any versioned files (e.g. .md, .xml, .txt, .html)
    files = list(Path('.').glob(f"{prefix}-*"))
    if not files:
        return -1
    
    versions = []
    for f in files:
        # Match - followed by exactly 2 or more digits at the end before extension
        match = re.search(r'-(\d+)(\.\w+)?$', f.name)
        if match:
            versions.append(int(match.group(1)))
    
    return max(versions) if versions else -1

def update_metadata(file_path, new_version_str, doc_name_base):
    """Updates docName and seriesInfo value in the markdown file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    new_doc_name = f"{doc_name_base}-{new_version_str}"
    
    # Update docName
    content = re.sub(r'docName\s*=\s*"[^"]+"', f'docName = "{new_doc_name}"', content)
    
    # Update seriesInfo value
    content = re.sub(r'value\s*=\s*"[^"]+"', f'value = "{new_doc_name}"', content)
    
    with open(file_path, 'w') as f:
        f.write(content)
    print(f"Updated metadata in {file_path} to version {new_version_str}")

def run_command(command, description):
    """Runs a shell command and handles errors."""
    print(f"Executing: {description}...")
    try:
        subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error during {description}:")
        print(e.stderr)
        sys.exit(1)

def perform_cleanup(prefix, target_version_str, remove_current_md=True):
    """Removes old generated files and optionally the current versioned .md."""
    print("Cleaning up redundant versioned files...")
    extensions = ['.xml', '.html', '.txt', '.md']
    
    # 1. Remove artifacts from ALL other versions
    for f in Path('.').glob(f"{prefix}-*"):
        # Don't delete the master
        if f.name == f"{prefix}.md":
            continue
            
        # Is this a versioned file?
        match = re.search(r'-(\d+)(\.\w+)?$', f.name)
        if not match:
            continue
            
        version_in_file = match.group(1)
        
        # If it's a different version, delete it if it matches our target extensions
        if version_in_file != target_version_str:
            if f.suffix in extensions:
                try:
                    f.unlink()
                    print(f"Removed old version file: {f.name}")
                except Exception as e:
                    print(f"Warning: Could not remove {f.name}: {e}")
        
        # If it's the CURRENT versioned .md, delete it (we have the artifacts and the master)
        elif remove_current_md and f.suffix == '.md':
            try:
                f.unlink()
                print(f"Removed current versioned source (redundant): {f.name}")
            except Exception as e:
                print(f"Warning: Could not remove {f.name}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Automate IETF draft release (Compile & Push).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:

1. Compile master file, update current version, commit, and push:
   $ ./release_draft.py

2. Increment the version (bump), build, commit, and push:
   $ ./release_draft.py --bump

3. Dry run to see what would be targeted:
   $ ./release_draft.py --dry-run
"""
    )
    parser.add_argument("--source", default=SOURCE, help=f"The master .md file (default: {SOURCE}).")
    parser.add_argument("--prefix", help="The draft prefix.")
    parser.add_argument("--version", default=VERSION, help="Explicitly set the version number.")
    parser.add_argument("--bump", action="store_true", default=AUTO_BUMP, help=f"Increment version (default: {AUTO_BUMP}).")
    parser.add_argument("--no-push", action="store_true", help="Disable git push.")
    parser.add_argument("--cleanup", action="store_true", default=CLEANUP, help=f"Clean old generated files (default: {CLEANUP}).")
    parser.add_argument("--no-cleanup", action="store_false", dest="cleanup", help="Disable cleanup.")
    parser.add_argument("--dry-run", action="store_true", help="Dry run.")
    
    args = parser.parse_args()
    should_push = PUSH and not args.no_push
    should_cleanup = args.cleanup

    if not args.prefix:
        md_files = list(Path('.').glob("draft-*.md"))
        if md_files:
            prefixes = set()
            for f in md_files:
                match = re.match(r'(draft-.*?)-\d+\.md', f.name)
                if match:
                    prefixes.add(match.group(1))
            if len(prefixes) == 1:
                args.prefix = list(prefixes)[0]
                print(f"Inferred prefix: {args.prefix}")
            else:
                print("Error: Could not infer prefix. Specify --prefix.")
                sys.exit(1)
        else:
            print("Error: No versioned .md files found.")
            sys.exit(1)

    if args.version:
        target_version_str = args.version
    else:
        current_version = get_latest_version(args.prefix)
        if current_version < 0:
            target_version = 0
            print("Starting at 00.")
        else:
            target_version = current_version + (1 if args.bump else 0)
        target_version_str = f"{target_version:02d}"
    
    new_filename = f"{args.prefix}-{target_version_str}.md"
    print(f"Target version: {target_version_str} ({new_filename})")

    if args.dry_run:
        print("Dry run: Skipping operations.")
        return

    # 1. Copy source to versioned file
    source_file = None
    if args.source:
        if os.path.exists(args.source):
            source_file = args.source
        elif not args.source.endswith(".md") and os.path.exists(args.source + ".md"):
            source_file = args.source + ".md"
    
    if not source_file and args.prefix:
        potential = args.prefix + ".md"
        if os.path.exists(potential):
            source_file = potential
            print(f"Using source: {source_file}")

    if source_file:
        run_command(f"cp {source_file} {new_filename}", f"copying {source_file} to {new_filename}")
    elif current_version >= 0:
        prev = f"{args.prefix}-{current_version:02d}.md"
        run_command(f"cp {prev} {new_filename}", f"copying {prev}")
    else:
        print("Error: No source found.")
        sys.exit(1)

    # 2. Update metadata
    update_metadata(new_filename, target_version_str, args.prefix)

    # 3. Build
    if os.path.exists("Makefile"):
        draft_base = f"{args.prefix}-{target_version_str}"
        run_command(f"make DRAFT={draft_base}", f"running make for {draft_base}")
        if should_cleanup:
            perform_cleanup(args.prefix, target_version_str)
    else:
        print("Warning: Makefile not found.")

    # 4. Git operations
    run_command("git add .", "staging changes")
    commit_msg = f"Update version {target_version_str}"
    run_command(f'git commit -m "{commit_msg}"', f"committing update {target_version_str}")
    
    if should_push:
        run_command("git push", "pushing to remote")
        print("Release pushed successfully.")
    else:
        print("Changes committed locally (not pushed).")

if __name__ == "__main__":
    main()
