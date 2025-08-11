# File Deletion & Duplicate Management Guide

This guide explains how to delete duplicate files or wrong statements in your Personal Finance Manager.

## Overview

The Personal Finance Manager now includes comprehensive deletion and duplicate management features:

1. **File Import Management** - View and delete entire file imports
2. **Duplicate Detection** - Find and remove duplicate transactions  
3. **Individual Transaction Management** - Delete specific transactions

## Accessing Deletion Features

### File Management Tab

1. Open the application and authenticate with your password
2. Navigate to the **"File Management"** tab
3. This tab shows all your imported files and their current status

### Features Available

#### 1. View File Imports
- See all files you've imported with:
  - File name
  - Import date
  - Original transaction count
  - Current transaction count
  - Import status

#### 2. Delete Entire File Imports

**When to use:** 
- Accidentally imported the wrong file
- Imported a duplicate statement
- Need to re-import with corrections

**How to use:**
1. In the File Management tab, find the file you want to delete
2. Click the red **"Delete File Import"** button
3. Review the preview of transactions that will be deleted
4. Confirm the deletion

**⚠️ Warning:** This permanently deletes ALL transactions from that file import.

#### 3. Find and Remove Duplicates

**When to use:**
- Imported the same statement multiple times
- Overlapping statement periods
- Manual entry duplicates

**How to use:**
1. Click the **"Find Duplicates"** button in the File Management tab
2. Review potential duplicates (grouped by similar date, amount, and description)
3. Select which duplicate transactions to delete (keep at least one copy)
4. Click **"Delete Selected"** to remove chosen duplicates

**Smart Detection:**
- Finds transactions within 3 days of each other
- Matches amounts exactly (within 1 cent)
- Compares descriptions for similarity
- Groups duplicates for easy review

## Safety Features

### Backup Recommendations
Before deleting transactions:
1. Go to **File → Backup Database**
2. Save a backup to a safe location
3. This allows you to restore if you delete something by mistake

### Confirmation Dialogs
- All deletion operations show confirmation dialogs
- Preview exactly what will be deleted
- Cannot be undone once confirmed

### Import History
- All file imports are tracked in the database
- Shows original vs. current transaction count
- Deleted imports are marked as "deleted" status

## Step-by-Step Examples

### Example 1: Remove Duplicate File Import

**Scenario:** You accidentally imported your January credit card statement twice.

**Solution:**
1. Go to File Management tab
2. Find the duplicate January import (look for same filename/date)
3. Click "Delete File Import" on one of them
4. Review the transactions in the preview
5. Confirm deletion if they match the duplicate import

### Example 2: Clean Up Multiple Duplicates

**Scenario:** You imported several overlapping statements with duplicate transactions.

**Solution:**
1. Click "Find Duplicates" in File Management tab
2. Review the duplicate groups shown
3. For each group, select all but one transaction to delete
4. Use "Select All" then uncheck one from each group if needed
5. Click "Delete Selected"

### Example 3: Remove Wrong Statement

**Scenario:** You imported your spouse's statement by mistake.

**Solution:**
1. Find the incorrect import in File Management tab
2. Click "Delete File Import" 
3. All transactions from that statement will be removed
4. Re-import the correct statement

## Technical Details

### What Gets Deleted
- **Delete File Import:** All transactions with matching file hash
- **Delete Duplicates:** Selected individual transactions
- **File Import Record:** Status changes to "deleted" (record preserved for audit)

### Duplicate Detection Algorithm
- Date window: ±3 days
- Amount matching: Exact match (±$0.01)
- Description matching: Exact or first 10 characters
- Account matching: Same account only

### Database Impact
- Transactions are permanently removed from database
- File import audit trail preserved
- Category learning data may be affected
- Statistics and reports will update automatically

## Troubleshooting

### "No transactions found for this file import"
- The transactions may have been deleted already
- File import record exists but transactions are gone
- Check the "Current Count" column - should be 0

### "No duplicates found" 
- Your transactions are already unique
- Duplicate detection uses strict criteria
- Try manual review in Transactions tab

### Accidental Deletion
- Restore from backup (File → Restore Database)
- Re-import the original file if available
- No undo function for individual deletions

## Best Practices

1. **Always backup before major deletions**
2. **Review duplicate detection results carefully**
3. **Keep original statement files for re-import if needed**
4. **Delete file imports rather than individual transactions when possible**
5. **Use the preview feature to verify what will be deleted**

## Security Note

All deletion operations:
- Require database password authentication
- Use secure database transactions
- Maintain audit trail of import history
- Cannot be accessed without valid password
- Work entirely offline (no cloud sync to worry about)
