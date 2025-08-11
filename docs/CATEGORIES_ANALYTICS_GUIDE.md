# Categories & Analytics Guide

This guide explains how to use the Categories and Analytics features in your Personal Finance Manager.

## Overview

The Personal Finance Manager now includes two powerful tabs:

1. **Categories Tab** - Manage transaction categories for better organization
2. **Analytics Tab** - View financial insights, trends, and summaries

## Categories Tab

### Purpose
Categories help you organize and analyze your spending patterns. You can create income and expense categories to automatically classify your transactions.

### Default Categories
The system comes with pre-installed categories:
- **Expense Categories:** Food & Dining, Transportation, Shopping, Entertainment, Bills & Utilities, Healthcare
- **Income Categories:** Salary, Freelance, Investment (all under main "Income" category)

### Managing Categories

#### Adding New Categories
1. Navigate to the **Categories** tab
2. Click **"Add Category"** button
3. Fill in the category details:
   - **Category Name:** e.g., "Groceries", "Gas", "Bonus"
   - **Type:** Choose "Income" or "Expense"
   - **Parent Category:** Optional - select a parent for subcategories
4. Click **OK** to create

#### Example Category Structure
```
Income
├── Salary
├── Freelance
└── Investment

Transportation
├── Gas
├── Public Transit
└── Car Maintenance

Food & Dining
├── Groceries
├── Restaurants
└── Coffee
```

#### Deleting Categories
- Categories can only be deleted if they have **no associated transactions**
- Categories with child categories cannot be deleted
- Use the red **"Delete"** button next to unused categories
- Categories with transactions show the transaction count instead

#### Category Statistics
The bottom of the tab shows:
- **Total Categories:** Overall count
- **Income Categories:** Number of income categories
- **Expense Categories:** Number of expense categories

### Automatic Categorization
The ML categorizer automatically assigns categories to imported transactions based on:
- Transaction descriptions
- Amount patterns
- Previous user corrections
- Merchant names

## Analytics Tab

### Purpose
The Analytics tab provides comprehensive insights into your financial data with visual summaries and trend analysis.

### Time Period Controls
Choose your analysis timeframe:
- **Last 30 Days** - Recent activity
- **Last 90 Days** - Quarterly view
- **Last 6 Months** - Medium-term trends
- **Last Year** - Annual overview
- **All Time** - Complete history
- **Custom Range** - Specific dates (future enhancement)

### Account Filtering
- **All Accounts** - Combined view of all accounts
- **Specific Account** - Filter to see individual account data

### Summary Cards
Four key metrics at the top:

#### 1. Total Income (Green)
- Sum of all credit transactions in the selected period
- Includes salary, freelance, investments, etc.

#### 2. Total Expenses (Red)
- Sum of all debit transactions in the selected period
- All spending across categories

#### 3. Net Amount (Blue/Red)
- Income minus Expenses
- **Green** if positive (surplus)
- **Red** if negative (deficit)

#### 4. Transaction Count (Orange)
- Total number of transactions in the period

### Category Breakdown (Left Side)
**"Spending by Category" Table:**
- Shows expense categories ranked by spending amount
- **Amount Column:** Dollar amount spent per category
- **Percentage Column:** What portion of total spending
- Helps identify your biggest expense areas

**Example:**
```
Category          Amount    Percentage
Food & Dining    $1,245.67     35.2%
Transportation     $456.78     12.9%
Shopping          $334.21      9.4%
```

### Monthly Trends (Right Side)
**"Monthly Trends" Table:**
- Shows last 6 months of financial data
- **Month:** YYYY-MM format
- **Income:** Total income for the month
- **Expenses:** Total expenses for the month
- **Net:** Monthly surplus/deficit
  - **Green text:** Positive (surplus)
  - **Red text:** Negative (deficit)

**Example:**
```
Month     Income    Expenses    Net
2025-03   $5,200.00  $4,150.32  $1,049.68
2025-02   $5,200.00  $4,567.89   $632.11
2025-01   $5,200.00  $4,890.23   $309.77
```

### Recent Large Transactions (Bottom)
**"Recent Large Transactions" Table:**
- Top 10 largest transactions by amount
- Helps identify significant spending/income
- **Date:** When the transaction occurred
- **Description:** Transaction details (truncated to 40 characters)
- **Amount:** Transaction amount
- **Category:** Assigned category

## Using Categories and Analytics Together

### Workflow Example

1. **Import Statements**
   - Import your bank/credit card statements
   - Transactions are automatically categorized

2. **Review Categories**
   - Go to Categories tab
   - Add custom categories for your specific needs
   - Check that important categories exist

3. **Analyze Spending**
   - Go to Analytics tab
   - Select appropriate time period (e.g., "Last 90 Days")
   - Review spending by category
   - Identify areas for budget optimization

4. **Track Trends**
   - Use Monthly Trends to see patterns
   - Look for months with negative net amounts
   - Identify seasonal spending patterns

### Practical Applications

#### Budget Planning
- Use category breakdown to see where money goes
- Set spending targets based on percentages
- Track progress month-over-month

#### Expense Optimization
- Find categories with unexpectedly high spending
- Use large transactions table to spot unusual expenses
- Compare monthly trends to identify seasonal patterns

#### Financial Goals
- Monitor net income trends
- Identify months to increase savings
- Track progress toward financial targets

## Tips for Better Categorization

### Best Practices
1. **Create Specific Categories:** "Groceries" vs. generic "Food"
2. **Use Subcategories:** Group related expenses under main categories
3. **Be Consistent:** Don't create duplicate categories
4. **Regular Review:** Check uncategorized transactions periodically

### Common Categories to Consider
**Expenses:**
- Housing (Rent/Mortgage, Utilities, Maintenance)
- Transportation (Gas, Public Transit, Car Payment)
- Food (Groceries, Restaurants, Coffee)
- Healthcare (Insurance, Medical, Pharmacy)
- Personal (Clothing, Hair, Gym)
- Entertainment (Movies, Subscriptions, Hobbies)
- Financial (Banking Fees, Investment)

**Income:**
- Primary Job (Salary, Bonus)
- Side Income (Freelance, Gig Work)
- Passive (Dividends, Interest, Rental)
- Other (Tax Refund, Gifts, Sales)

## Data Privacy & Security

### Local Processing
- All analytics calculations happen locally on your device
- No data is sent to external servers
- Charts and summaries are generated from your encrypted database

### Performance
- Analytics update automatically when you:
  - Import new transactions
  - Change time periods
  - Switch account filters
- Large datasets may take a moment to process

### Backup Recommendations
- Analytics rely on your transaction data
- Regular database backups ensure you don't lose insights
- Use **File → Backup Database** before major changes

## Troubleshooting

### "No data available"
- Check if you have transactions in the selected time period
- Verify account filter isn't excluding all data
- Import some statements if database is empty

### Categories not showing
- Ensure transactions have been categorized
- Some transactions may be "Uncategorized"
- Re-run categorization on imported data

### Analytics not updating
- Click **"Refresh"** button in Analytics tab
- Change and change back the time period to force update
- Restart application if issues persist

## Future Enhancements

Planned features include:
- **Visual Charts:** Pie charts and bar graphs for spending
- **Budget Tracking:** Set and monitor spending limits
- **Goal Setting:** Track progress toward financial goals
- **Export Reports:** PDF/CSV export of analytics data
- **Custom Date Ranges:** Precise date selection
- **Comparison Views:** Year-over-year analysis

The current implementation provides a solid foundation for financial analysis and category management, with room for future expansion based on user needs.
