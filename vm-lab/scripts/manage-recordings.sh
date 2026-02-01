#!/bin/bash
# ==============================================================================
# Session Recordings Management Script
# ==============================================================================
# Utilities for managing session recordings:
# - List recordings
# - Search recordings by student
# - Clean up old recordings
# - Export recordings
# ==============================================================================

set -e

RECORDINGS_DIR="${RECORDINGS_DIR:-/var/lib/vm-lab/recordings}"
API_URL="${API_URL:-http://localhost:8000}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "Session Recordings Management"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  list [--email EMAIL] [--name NAME] [--course COURSE] [--date DATE]"
    echo "      List recordings with optional filters"
    echo ""
    echo "  stats"
    echo "      Show recording statistics"
    echo ""
    echo "  view <recording_id>"
    echo "      View recording content (stripped of ANSI codes)"
    echo ""
    echo "  replay <recording_id>"
    echo "      Download and replay a recording"
    echo ""
    echo "  export <recording_id> <output_dir>"
    echo "      Export recording files to a directory"
    echo ""
    echo "  cleanup [--days DAYS] [--dry-run]"
    echo "      Remove recordings older than DAYS (default: 90)"
    echo ""
    echo "  disk-usage"
    echo "      Show disk usage by month"
    echo ""
    echo "Examples:"
    echo "  $0 list --email jsmith"
    echo "  $0 list --date 2024-01-15"
    echo "  $0 replay 42"
    echo "  $0 cleanup --days 30 --dry-run"
}

cmd_list() {
    local params=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --email)
                params="${params}&user_email=$2"
                shift 2
                ;;
            --name)
                params="${params}&user_name=$2"
                shift 2
                ;;
            --course)
                params="${params}&course_id=$2"
                shift 2
                ;;
            --date)
                params="${params}&date_from=$2&date_to=$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    # Remove leading &
    params="${params#&}"

    echo "Fetching recordings..."
    response=$(curl -s "${API_URL}/api/recordings?${params}&limit=50")

    echo "$response" | python3 -c "
import json
import sys

data = json.load(sys.stdin)
recordings = data.get('recordings', [])
total = data.get('total', 0)

print(f'\\nTotal recordings: {total}\\n')
print('{:<6} {:<20} {:<30} {:<20} {:<10} {:<12}'.format(
    'ID', 'Student', 'Email', 'Course', 'Duration', 'Size'))
print('-' * 100)

for r in recordings:
    duration = f\"{r.get('duration_seconds', 0) // 60}m {r.get('duration_seconds', 0) % 60}s\" if r.get('duration_seconds') else 'N/A'
    size = f\"{r.get('file_size_bytes', 0) // 1024}KB\" if r.get('file_size_bytes') else 'N/A'
    print('{:<6} {:<20} {:<30} {:<20} {:<10} {:<12}'.format(
        r.get('id', ''),
        (r.get('user_name', '') or 'Unknown')[:19],
        (r.get('user_email', '') or 'Unknown')[:29],
        (r.get('course_title', '') or 'Unknown')[:19],
        duration,
        size
    ))
"
}

cmd_stats() {
    echo "Fetching statistics..."
    response=$(curl -s "${API_URL}/api/stats")

    echo "$response" | python3 -c "
import json
import sys

data = json.load(sys.stdin)

print('\\n=== Recording Statistics ===')
print(f\"Total recordings: {data.get('total_recordings', 0)}\")
print(f\"Completed: {data.get('completed_recordings', 0)}\")
print(f\"Total size: {data.get('total_recording_size_mb', 0):.2f} MB\")
print()
"

    # Disk usage
    if [ -d "$RECORDINGS_DIR" ]; then
        echo "=== Disk Usage ==="
        du -sh "$RECORDINGS_DIR" 2>/dev/null || echo "Cannot access recordings directory"
        echo ""
        echo "By month:"
        find "$RECORDINGS_DIR" -name "*.log" -type f 2>/dev/null | \
            sed 's|.*/\([0-9]\{4\}\)/\([0-9]\{2\}\)/.*|\1-\2|' | \
            sort | uniq -c | sort -k2
    fi
}

cmd_view() {
    local recording_id=$1

    if [ -z "$recording_id" ]; then
        echo -e "${RED}Error: Recording ID required${NC}"
        exit 1
    fi

    echo "Fetching recording $recording_id..."
    curl -s "${API_URL}/api/recordings/${recording_id}/view"
}

cmd_replay() {
    local recording_id=$1
    local tmpdir=$(mktemp -d)

    if [ -z "$recording_id" ]; then
        echo -e "${RED}Error: Recording ID required${NC}"
        exit 1
    fi

    echo "Downloading recording files..."
    curl -s -o "${tmpdir}/session.log" "${API_URL}/api/recordings/${recording_id}/download"
    curl -s -o "${tmpdir}/session.timing" "${API_URL}/api/recordings/${recording_id}/timing"

    if [ ! -s "${tmpdir}/session.log" ]; then
        echo -e "${RED}Error: Failed to download recording${NC}"
        rm -rf "$tmpdir"
        exit 1
    fi

    echo -e "${GREEN}Starting replay (Ctrl+C to stop)...${NC}"
    echo ""

    scriptreplay "${tmpdir}/session.timing" "${tmpdir}/session.log" 2>/dev/null || \
        echo -e "${YELLOW}Note: scriptreplay not available, showing raw log:${NC}" && \
        cat "${tmpdir}/session.log"

    rm -rf "$tmpdir"
}

cmd_export() {
    local recording_id=$1
    local output_dir=$2

    if [ -z "$recording_id" ] || [ -z "$output_dir" ]; then
        echo -e "${RED}Error: Recording ID and output directory required${NC}"
        exit 1
    fi

    mkdir -p "$output_dir"

    echo "Exporting recording $recording_id to $output_dir..."

    # Get recording info
    info=$(curl -s "${API_URL}/api/recordings/${recording_id}")
    echo "$info" > "${output_dir}/info.json"

    # Download files
    curl -s -o "${output_dir}/session.log" "${API_URL}/api/recordings/${recording_id}/download"
    curl -s -o "${output_dir}/session.timing" "${API_URL}/api/recordings/${recording_id}/timing"

    echo -e "${GREEN}Exported to ${output_dir}${NC}"
    ls -la "$output_dir"
}

cmd_cleanup() {
    local days=90
    local dry_run=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --days)
                days=$2
                shift 2
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            *)
                shift
                ;;
        esac
    done

    echo "Finding recordings older than $days days..."

    if [ ! -d "$RECORDINGS_DIR" ]; then
        echo -e "${RED}Error: Recordings directory not found: $RECORDINGS_DIR${NC}"
        exit 1
    fi

    old_files=$(find "$RECORDINGS_DIR" -name "*.log" -type f -mtime +$days 2>/dev/null)
    count=$(echo "$old_files" | grep -c . || echo 0)

    if [ "$count" -eq 0 ]; then
        echo -e "${GREEN}No recordings older than $days days found.${NC}"
        exit 0
    fi

    echo "Found $count recordings to clean up:"

    total_size=0
    while IFS= read -r file; do
        if [ -n "$file" ]; then
            size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)
            total_size=$((total_size + size))
            timing_file="${file%.log}.timing"

            if $dry_run; then
                echo "  [DRY RUN] Would remove: $file"
            else
                rm -f "$file" "$timing_file"
                echo "  Removed: $file"
            fi
        fi
    done <<< "$old_files"

    size_mb=$((total_size / 1024 / 1024))

    if $dry_run; then
        echo -e "${YELLOW}Dry run complete. Would free ${size_mb}MB${NC}"
    else
        echo -e "${GREEN}Cleanup complete. Freed ${size_mb}MB${NC}"
    fi
}

cmd_disk_usage() {
    if [ ! -d "$RECORDINGS_DIR" ]; then
        echo -e "${RED}Error: Recordings directory not found: $RECORDINGS_DIR${NC}"
        exit 1
    fi

    echo "=== Recording Disk Usage ==="
    echo ""

    echo "Total:"
    du -sh "$RECORDINGS_DIR"
    echo ""

    echo "By year/month:"
    for year_dir in "$RECORDINGS_DIR"/*/; do
        if [ -d "$year_dir" ]; then
            year=$(basename "$year_dir")
            for month_dir in "$year_dir"/*/; do
                if [ -d "$month_dir" ]; then
                    month=$(basename "$month_dir")
                    size=$(du -sh "$month_dir" 2>/dev/null | cut -f1)
                    count=$(find "$month_dir" -name "*.log" -type f 2>/dev/null | wc -l)
                    echo "  $year-$month: $size ($count recordings)"
                fi
            done
        fi
    done
}

# Main
case "${1:-}" in
    list)
        shift
        cmd_list "$@"
        ;;
    stats)
        cmd_stats
        ;;
    view)
        shift
        cmd_view "$@"
        ;;
    replay)
        shift
        cmd_replay "$@"
        ;;
    export)
        shift
        cmd_export "$@"
        ;;
    cleanup)
        shift
        cmd_cleanup "$@"
        ;;
    disk-usage)
        cmd_disk_usage
        ;;
    *)
        usage
        ;;
esac
