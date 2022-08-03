package pkg

import (
	"errors"
	"time"

	"xorm.io/xorm"
)

type Value struct {
	Title            string         `json:",omitempty"`
	Description      string         `json:",omitempty"`
	Severity         string         `json:",omitempty"` // Selected from VendorSeverity, depending on a scan target
	CweIDs           []string       `json:",omitempty"` // e.g. CWE-78, CWE-89
	VendorSeverity   VendorSeverity `json:",omitempty"`
	CVSS             VendorCVSS     `json:",omitempty"`
	References       []string       `json:",omitempty"`
	PublishedDate    *time.Time     `json:",omitempty"` // Take from NVD
	LastModifiedDate *time.Time     `json:",omitempty"` // Take from NVD

	// Custom is basically for extensibility and is not supposed to be used in OSS
	Custom interface{} `json:",omitempty"`
}

// SourceID represents data source such as NVD.
type SourceID string
type Severity int
type VendorSeverity map[SourceID]Severity

//CVSS 漏洞评分等级，有几种表达方式（nvd/redhat）
type CVSS struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}
type VendorCVSS map[SourceID]CVSS

type Vulnerability struct {
	Id               int64
	Cve              string         `xorm:"varchar(30)"`
	Title            string         `xorm:"text"`
	Description      string         `xorm:"text"`
	Severity         string         `xorm:"varchar(30)"` // Selected from VendorSeverity, depending on a scan target
	CweIDs           []string       `xorm:"text"`        // e.g. CWE-78, CWE-89
	VendorSeverity   VendorSeverity `xorm:"text"`
	CVSS             VendorCVSS     `xorm:"text"`
	References       []string       `xorm:"text"`
	PublishedDate    *time.Time     `xorm:"DateTime"` // Take from NVD
	LastModifiedDate *time.Time     `xorm:"DateTime"` // Take from NVD
}

// DataSource 漏洞信息来源
type DataSource struct {
	ID   SourceID `json:",omitempty"`
	Name string   `json:",omitempty"`
	URL  string   `json:",omitempty"`
}

// Advisory 有关漏洞的建议，实际上是初筛报告
// 后面会根据的版本进行筛选
type Advisory struct {
	// 对应的CVE ID
	VulnerabilityID string `json:",omitempty"` // CVE-ID or vendor ID
	// 其他的厂商对应的ID
	VendorIDs []string `json:",omitempty"` // e.g. RHSA-ID and DSA-ID

	// Rpm packages have advisories for different architectures with same package name
	// This field is required to separate these packages.
	Arches []string `json:"-"`

	// It is filled only when FixedVersion is empty since it is obvious the state is "Fixed" when FixedVersion is not empty.
	// e.g. Will not fix and Affected
	State string `json:",omitempty"`

	// Trivy DB has "vulnerability" bucket and severities are usually stored in the bucket per a vulnerability ID.
	// In some cases, the advisory may have multiple severities depending on the packages.
	// For example, CVE-2015-2328 in Debian has "unimportant" for mongodb and "low" for pcre3.
	// e.g. https://security-tracker.debian.org/tracker/CVE-2015-2328
	Severity Severity `json:",omitempty"`

	// Versions for os package
	FixedVersion    string `json:",omitempty"`
	AffectedVersion string `json:",omitempty"` // Only for Arch Linux

	// MajorVersion ranges for language-specific package
	// Some advisories provide VulnerableVersions only, others provide PatchedVersions and UnaffectedVersions
	VulnerableVersions []string `json:",omitempty"`
	PatchedVersions    []string `json:",omitempty"`
	UnaffectedVersions []string `json:",omitempty"`

	// DataSource holds where the advisory comes from
	DataSource *DataSource `json:",omitempty"`

	// Custom is basically for extensibility and is not supposed to be used in OSS
	Custom interface{} `json:",omitempty"`
}

type VulnerabilityAdvisory struct {
	Id                 int64
	Cve                string      `xorm:"varchar(30)"`
	Platform           string      `xorm:"varchar(50)"`
	Segment            string      `xorm:"varchar(50)"`
	PackageName        string      `xorm:"varchar(100)"`
	VulnerabilityID    string      `xorm:"text"` // CVE-ID or vendor ID
	VendorIDs          []string    `xorm:"text"` // e.g. RHSA-ID and DSA-ID
	Arches             []string    `xorm:"text"`
	State              string      `xorm:"text"`
	Severity           Severity    `xorm:"text"`
	FixedVersion       string      `xorm:"text"`
	AffectedVersion    string      `xorm:"text"` // Only for Arch Linux
	VulnerableVersions []string    `xorm:"text"`
	PatchedVersions    []string    `xorm:"text"`
	UnaffectedVersions []string    `xorm:"text"`
	DataSource         *DataSource `xorm:"text"`
}

func Insert(engine xorm.Engine, i interface{}) error {
	var err error
	switch data := i.(type) {
	case Vulnerability:
		_, err = engine.Insert(data)
	case VulnerabilityAdvisory:
		_, err = engine.Insert(data)
	default:
		return errors.New("wrong type, insert error")
	}
	if err != nil {
		return err
	}
	return nil
}

func DropTables(engine *xorm.Engine) error {
	return engine.DropTables(new(Vulnerability), new(VulnerabilityAdvisory))
}
