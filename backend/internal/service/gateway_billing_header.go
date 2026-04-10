package service

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/cespare/xxhash/v2"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ccVersionInBillingRe matches the semver part of cc_version (X.Y.Z), preserving
// the trailing message-derived suffix (e.g. ".c02") if present.
var ccVersionInBillingRe = regexp.MustCompile(`cc_version=\d+\.\d+\.\d+`)

// cchPlaceholderRe matches the cch=00000 placeholder in billing header text,
// scoped to x-anthropic-billing-header to avoid touching user content.
var cchPlaceholderRe = regexp.MustCompile(`(x-anthropic-billing-header:[^"]*?\bcch=)(00000)(;)`)

const cchSeed uint64 = 0x6E52736AC806831E

// syncBillingHeaderVersion rewrites cc_version in x-anthropic-billing-header
// system text blocks to match the version extracted from userAgent.
// Only touches system array blocks whose text starts with "x-anthropic-billing-header".
func syncBillingHeaderVersion(body []byte, userAgent string) []byte {
	version := ExtractCLIVersion(userAgent)
	if version == "" {
		return body
	}

	systemResult := gjson.GetBytes(body, "system")
	if !systemResult.Exists() || !systemResult.IsArray() {
		return body
	}

	replacement := "cc_version=" + version
	idx := 0
	systemResult.ForEach(func(_, item gjson.Result) bool {
		text := item.Get("text")
		if text.Exists() && text.Type == gjson.String &&
			strings.HasPrefix(text.String(), "x-anthropic-billing-header") {
			newText := ccVersionInBillingRe.ReplaceAllString(text.String(), replacement)
			if newText != text.String() {
				if updated, err := sjson.SetBytes(body, fmt.Sprintf("system.%d.text", idx), newText); err == nil {
					body = updated
				}
			}
		}
		idx++
		return true
	})

	return body
}

// signBillingHeaderCCH computes the xxHash64-based CCH signature for the request
// body and replaces the cch=00000 placeholder with the computed 5-hex-char hash.
// The body must contain the placeholder when this function is called.
func signBillingHeaderCCH(body []byte) []byte {
	if !cchPlaceholderRe.Match(body) {
		return body
	}
	cch := fmt.Sprintf("%05x", xxHash64Seeded(body, cchSeed)&0xFFFFF)
	return cchPlaceholderRe.ReplaceAll(body, []byte("${1}"+cch+"${3}"))
}

// xxHash64Seeded computes xxHash64 of data with a custom seed.
func xxHash64Seeded(data []byte, seed uint64) uint64 {
	d := xxhash.NewWithSeed(seed)
	_, _ = d.Write(data)
	return d.Sum64()
}

// DefaultCLIVersion 当无法从 User-Agent 提取版本时使用的默认版本号。
const DefaultCLIVersion = "2.1.81"

// cchFieldRe matches any " cch=XXXXX;" segment in billing header text (placeholder or signed).
// Used by stripBillingHeaderCCH to remove the cch field entirely.
var cchFieldRe = regexp.MustCompile(`(x-anthropic-billing-header:[^"]*?) cch=[0-9a-fA-F]{5};`)

// stripBillingHeaderCCH removes the cch field from billing header text in the request body.
// This is used when enable_cch_signing is false to avoid sending cch=00000 placeholder
// which is an obvious forgery signal. Real Claude Code without NATIVE_CLIENT_ATTESTATION
// simply omits the cch field entirely.
func stripBillingHeaderCCH(body []byte) []byte {
	return cchFieldRe.ReplaceAll(body, []byte("${1}"))
}

// BuildBillingHeaderText 为 mimic 模式构造 billing header 系统文本。
// 格式与非 Bun 环境的真实 Claude Code 一致（不含 cch 字段）：
//
//	x-anthropic-billing-header: cc_version={VER}.{FP}; cc_entrypoint=cli;
//
// 其中 VER 是 CLI 版本号，FP 是 3 字符消息指纹。
func BuildBillingHeaderText(body []byte, userAgent string) string {
	version := ExtractCLIVersion(userAgent)
	if version == "" {
		version = DefaultCLIVersion
	}
	fp := claude.ComputeMessageFingerprintFromBody(body, version)
	return fmt.Sprintf("x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=cli;", version, fp)
}
