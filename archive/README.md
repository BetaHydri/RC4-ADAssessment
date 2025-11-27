# Archive - Legacy v1.0 Files

This folder contains the original v1.0 files for historical reference and compatibility.

## ⚠️ Important Notice

**These files are legacy/archived versions. Please use v2.0 instead:**

➡️ **[Back to v2.0 Documentation](../README.md)**

## Files in This Archive

### RC4_AD_SCAN_v1_LEGACY.ps1
- Original v1.0 script
- **Runtime:** 5.5+ hours in large environments
- **Logic:** Pre-November 2022 Kerberos assumptions
- **Use Case:** Legacy compatibility only

### README_v1_LEGACY.md
- Complete v1.0 documentation
- Comprehensive usage guide
- Original feature set documentation

## Why v2.0?

| Aspect | v1.0 (Legacy) | v2.0 (Current) |
|--------|---------------|----------------|
| **Performance** | 5.5+ hours | < 5 minutes |
| **Accuracy** | Pre-Nov 2022 logic | Post-Nov 2022 accurate |
| **Event Analysis** | None | Real usage detection |
| **False Positives** | High | Low |
| **Export/Tracking** | Limited CSV | JSON + CSV + Comparison |

## Migration Guide

### Quick Migration

Instead of:
```powershell
.\RC4_AD_SCAN.ps1
```

Use:
```powershell
# v2.0 Quick Assessment
..\RC4_DES_Assessment.ps1 -QuickScan

# v2.0 Full Assessment
..\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults

# v2.0 Compare Results Over Time
..\Compare-Assessments.ps1 -BaselineFile old.json -CurrentFile new.json
```

### When to Use v1.0

Consider using v1.0 **only** if:
- Compliance requires explicit computer object enumeration
- You need pre-November 2022 assessment methodology for comparison
- Specific compatibility requirements with v1.0 tooling

**Note:** Even for these scenarios, v2.0 provides more accurate results with post-November 2022 logic.

## Support

For v1.0 support or questions, please see:
- [v1.0 Documentation](README_v1_LEGACY.md)
- [v2.0 Documentation](../README.md) (recommended)

## Version History

- **v1.0** (October 2025) - Initial release, archived here
- **v2.0** (November 2025) - Complete rewrite, current version

---

**Recommendation:** Use [v2.0](../README.md) for all new assessments. Legacy files maintained for reference only.
