#!/bin/bash
#
# Final Cleanup - Remove all personal information and unnecessary files
#

echo "Removing personal information and unnecessary files..."

# Remove any remaining personal paths in logs
find . -name "*.log" -type f -delete 2>/dev/null || true

# Remove build artifacts
rm -rf build/ 2>/dev/null || true

# Remove Python cache
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Remove git history (contains personal info)
rm -rf .git/ 2>/dev/null || true

# Remove temporary files
find . -name "*.d" -type f -delete 2>/dev/null || true
find . -name "*.o" -type f -delete 2>/dev/null || true
find . -name "*~" -type f -delete 2>/dev/null || true

echo "✓ Cleanup complete!"
echo ""
echo "Project is now clean and ready for distribution."
echo "Run './run_demo.sh' to start the demonstration."
