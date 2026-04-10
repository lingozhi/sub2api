package claude

import (
	"crypto/sha256"
	"encoding/hex"
	"unicode/utf16"

	"github.com/tidwall/gjson"
)

// FingerprintSalt 是 Claude Code 后端校验使用的固定盐值。
// 必须与 cc/utils/fingerprint.ts 中的 FINGERPRINT_SALT 完全一致。
const FingerprintSalt = "59cf53e54c78"

// ComputeMessageFingerprint 计算 3 字符的消息指纹。
// 算法：SHA256(SALT + text[4] + text[7] + text[20] + version)[:3]
// 其中 text[i] 按 UTF-16 code unit 索引取值（与 JavaScript string[i] 行为一致）。
// 若索引越界，使用 "0" 代替。
func ComputeMessageFingerprint(firstUserMessageText, version string) string {
	// 将文本转为 UTF-16 code unit 数组，对齐 JavaScript 的 string[i] 行为
	codeUnits := utf16.Encode([]rune(firstUserMessageText))

	indices := [3]int{4, 7, 20}
	var chars string
	for _, i := range indices {
		if i < len(codeUnits) {
			chars += string(rune(codeUnits[i]))
		} else {
			chars += "0"
		}
	}

	input := FingerprintSalt + chars + version
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:3]
}

// ExtractFirstUserMessageText 从 Anthropic 格式的请求 body 中提取第一条 user 消息文本。
// 严格遵循 cc/utils/fingerprint.ts 的 extractFirstMessageText 逻辑：
//  1. 遍历 messages 数组，找到第一个 role="user" 的消息
//  2. content 是 string → 直接使用
//  3. content 是 array → 找到第一个 type="text" 的 block，取其 text
//  4. 未找到则返回空字符串
func ExtractFirstUserMessageText(body []byte) string {
	var text string
	messagesResult := gjson.GetBytes(body, "messages")
	if !messagesResult.Exists() || !messagesResult.IsArray() {
		return ""
	}

	messagesResult.ForEach(func(_, msg gjson.Result) bool {
		if msg.Get("role").String() != "user" {
			return true // continue
		}

		content := msg.Get("content")
		switch {
		case content.Type == gjson.String:
			text = content.String()
		case content.IsArray():
			content.ForEach(func(_, block gjson.Result) bool {
				if block.Get("type").String() == "text" {
					text = block.Get("text").String()
					return false // break
				}
				return true // continue
			})
		}
		return false // 找到第一个 user 消息即停止
	})

	return text
}

// ComputeMessageFingerprintFromBody 便捷函数：从请求 body 提取文本并计算指纹。
func ComputeMessageFingerprintFromBody(body []byte, version string) string {
	text := ExtractFirstUserMessageText(body)
	return ComputeMessageFingerprint(text, version)
}
