// 包含比特币脚本语言中所有操作码的实现。

package txscript

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/ripemd160"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// 操作码定义与 txscript 操作码相关的信息。
// opfunc（如果存在）是调用以在脚本上执行操作码的函数。
// 当前脚本作为切片传入，第一个成员是操作码本身。
type opcode struct {
	value  byte
	name   string
	length int
	opfunc func(*opcode, []byte, *Engine) error
}

// 这些常量是 btc wiki、比特币核心以及大多数（如果不是所有）其他与处理 BTC 脚本相关的参考资料和软件中使用的官方操作码的值。
const (
	OP_0            = 0x00 // 0 - 表示数字0
	OP_FALSE        = 0x00 // 0 - 也称为OP_0，表示布尔值假
	OP_DATA_1       = 0x01 // 1 - 接下来的1个字节是数据
	OP_DATA_2       = 0x02 // 2
	OP_DATA_3       = 0x03 // 3
	OP_DATA_4       = 0x04 // 4
	OP_DATA_5       = 0x05 // 5
	OP_DATA_6       = 0x06 // 6
	OP_DATA_7       = 0x07 // 7
	OP_DATA_8       = 0x08 // 8
	OP_DATA_9       = 0x09 // 9
	OP_DATA_10      = 0x0a // 10
	OP_DATA_11      = 0x0b // 11
	OP_DATA_12      = 0x0c // 12
	OP_DATA_13      = 0x0d // 13
	OP_DATA_14      = 0x0e // 14
	OP_DATA_15      = 0x0f // 15
	OP_DATA_16      = 0x10 // 16
	OP_DATA_17      = 0x11 // 17
	OP_DATA_18      = 0x12 // 18
	OP_DATA_19      = 0x13 // 19
	OP_DATA_20      = 0x14 // 20
	OP_DATA_21      = 0x15 // 21
	OP_DATA_22      = 0x16 // 22
	OP_DATA_23      = 0x17 // 23
	OP_DATA_24      = 0x18 // 24
	OP_DATA_25      = 0x19 // 25
	OP_DATA_26      = 0x1a // 26
	OP_DATA_27      = 0x1b // 27
	OP_DATA_28      = 0x1c // 28
	OP_DATA_29      = 0x1d // 29
	OP_DATA_30      = 0x1e // 30
	OP_DATA_31      = 0x1f // 31
	OP_DATA_32      = 0x20 // 32
	OP_DATA_33      = 0x21 // 33
	OP_DATA_34      = 0x22 // 34
	OP_DATA_35      = 0x23 // 35
	OP_DATA_36      = 0x24 // 36
	OP_DATA_37      = 0x25 // 37
	OP_DATA_38      = 0x26 // 38
	OP_DATA_39      = 0x27 // 39
	OP_DATA_40      = 0x28 // 40
	OP_DATA_41      = 0x29 // 41
	OP_DATA_42      = 0x2a // 42
	OP_DATA_43      = 0x2b // 43
	OP_DATA_44      = 0x2c // 44
	OP_DATA_45      = 0x2d // 45
	OP_DATA_46      = 0x2e // 46
	OP_DATA_47      = 0x2f // 47
	OP_DATA_48      = 0x30 // 48
	OP_DATA_49      = 0x31 // 49
	OP_DATA_50      = 0x32 // 50
	OP_DATA_51      = 0x33 // 51
	OP_DATA_52      = 0x34 // 52
	OP_DATA_53      = 0x35 // 53
	OP_DATA_54      = 0x36 // 54
	OP_DATA_55      = 0x37 // 55
	OP_DATA_56      = 0x38 // 56
	OP_DATA_57      = 0x39 // 57
	OP_DATA_58      = 0x3a // 58
	OP_DATA_59      = 0x3b // 59
	OP_DATA_60      = 0x3c // 60
	OP_DATA_61      = 0x3d // 61
	OP_DATA_62      = 0x3e // 62
	OP_DATA_63      = 0x3f // 63
	OP_DATA_64      = 0x40 // 64
	OP_DATA_65      = 0x41 // 65
	OP_DATA_66      = 0x42 // 66
	OP_DATA_67      = 0x43 // 67
	OP_DATA_68      = 0x44 // 68
	OP_DATA_69      = 0x45 // 69
	OP_DATA_70      = 0x46 // 70
	OP_DATA_71      = 0x47 // 71
	OP_DATA_72      = 0x48 // 72
	OP_DATA_73      = 0x49 // 73
	OP_DATA_74      = 0x4a // 74
	OP_DATA_75      = 0x4b // 75 - 接下来的75个字节是数据
	OP_PUSHDATA1    = 0x4c // 76 - 接下来的一个字节长度值表示的字节数是数据
	OP_PUSHDATA2    = 0x4d // 77 - 接下来的两个字节长度值表示的字节数是数据
	OP_PUSHDATA4    = 0x4e // 78 - 接下来的四个字节长度值表示的字节数是数据
	OP_1NEGATE      = 0x4f // 79 - 表示数字-1
	OP_RESERVED     = 0x50 // 80 - 保留操作码，未使用
	OP_1            = 0x51 // 81 - 表示数字1
	OP_TRUE         = 0x51 // 81 - 也称为OP_1，表示布尔值真
	OP_2            = 0x52 // 82 - 表示数字2
	OP_3            = 0x53 // 83
	OP_4            = 0x54 // 84
	OP_5            = 0x55 // 85
	OP_6            = 0x56 // 86
	OP_7            = 0x57 // 87
	OP_8            = 0x58 // 88
	OP_9            = 0x59 // 89
	OP_10           = 0x5a // 90
	OP_11           = 0x5b // 91
	OP_12           = 0x5c // 92
	OP_13           = 0x5d // 93
	OP_14           = 0x5e // 94
	OP_15           = 0x5f // 95
	OP_16           = 0x60 // 96 - 表示数字16
	OP_NOP          = 0x61 // 97 - 无操作
	OP_VER          = 0x62 // 98 - 保留操作码，未使用
	OP_IF           = 0x63 // 99 - if语句开始
	OP_NOTIF        = 0x64 // 100 - if not语句开始
	OP_VERIF        = 0x65 // 101 - 保留操作码，未使用
	OP_VERNOTIF     = 0x66 // 102 - 保留操作码，未使用
	OP_ELSE         = 0x67 // 103 - else语句开始
	OP_ENDIF        = 0x68 // 104 - if语句结束
	OP_VERIFY       = 0x69 // 105 - 验证栈顶元素是否为真，为假则失败
	OP_RETURN       = 0x6a // 106 - 终止脚本并标记交易为无效
	OP_TOALTSTACK   = 0x6b // 107 - 将栈顶元素移至副栈
	OP_FROMALTSTACK = 0x6c // 108 - 将副栈顶元素移至主栈
	OP_2DROP        = 0x6d // 109 - 丢弃栈顶的两个元素
	OP_2DUP         = 0x6e // 110 - 复制栈顶的两个元素
	OP_3DUP         = 0x6f // 111 - 复制栈顶的三个元素
	OP_2OVER        = 0x70 // 112 - 复制栈中的第二对元素
	OP_2ROT         = 0x71 // 113 - 将栈中的第三对元素移至栈顶
	OP_2SWAP        = 0x72 // 114 - 交换栈顶的两对元素
	OP_IFDUP        = 0x73 // 115 - 如果栈顶元素为真，则复制它
	OP_DEPTH        = 0x74 // 116 - 将栈的大小压入栈顶
	OP_DROP         = 0x75 // 117 - 丢弃栈顶元素
	OP_DUP          = 0x76 // 118 - 复制栈顶元素
	OP_NIP          = 0x77 // 119 - 丢弃栈顶第二个元素
	OP_OVER         = 0x78 // 120 - 复制栈顶第二个元素
	OP_PICK         = 0x79 // 121 - 复制栈中指定位置的元素
	OP_ROLL         = 0x7a // 122 - 将栈中指定位置的元素移至栈顶
	OP_ROT          = 0x7b // 123 - 循环移动栈顶的三个元素
	OP_SWAP         = 0x7c // 124 - 交换栈顶的两个元素
	OP_TUCK         = 0x7d // 125 - 将栈顶元素插入到第二个元素之前
	// OP_CAT 到 OP_TUCK 为禁用操作码，不应在脚本中使用
	OP_CAT    = 0x7e // 126 - 连接两个字符串，已禁用
	OP_SUBSTR = 0x7f // 127 - 截取字符串的子串，已禁用
	OP_LEFT   = 0x80 // 128 - 保留字符串的左侧部分，已禁用
	OP_RIGHT  = 0x81 // 129 - 保留字符串的右侧部分，已禁用
	OP_SIZE   = 0x82 // 130 - 返回字符串的长度
	// OP_INVERT 到 OP_2MUL 为禁用操作码，不应在脚本中使用
	OP_INVERT      = 0x83 // 131 - 按位求反操作，已禁用
	OP_AND         = 0x84 // 132 - 按位与操作，已禁用
	OP_OR          = 0x85 // 133 - 按位或操作，已禁用
	OP_XOR         = 0x86 // 134 - 按位异或操作，已禁用
	OP_EQUAL       = 0x87 // 135 - 检查栈顶两个元素是否相等
	OP_EQUALVERIFY = 0x88 // 136 - 相等验证，等同于OP_EQUAL OP_VERIFY组合
	OP_RESERVED1   = 0x89 // 137 - 保留操作码，未使用
	OP_RESERVED2   = 0x8a // 138 - 保留操作码，未使用
	// OP_1ADD 到 OP_2DIV 为数字操作相关操作码
	OP_1ADD      = 0x8b // 139 - 栈顶元素加1
	OP_1SUB      = 0x8c // 140
	OP_2MUL      = 0x8d // 141
	OP_2DIV      = 0x8e // 142 - 栈顶元素除以2，已禁用
	OP_NEGATE    = 0x8f // 143 - 栈顶元素取反
	OP_ABS       = 0x90 // 144 - 栈顶元素取绝对值
	OP_NOT       = 0x91 // 145 - 栈顶元素取逻辑非
	OP_0NOTEQUAL = 0x92 // 146 - 检查栈顶元素是否不为0
	OP_ADD       = 0x93 // 147 - 加法操作
	OP_SUB       = 0x94 // 148 - 减法操作
	// OP_MUL 到 OP_MOD 为禁用操作码，不应在脚本中使用
	OP_MUL = 0x95 // 149 - 乘法操作，已禁用
	OP_DIV = 0x96 // 150
	OP_MOD = 0x97 // 151 - 取模操作，已禁用
	// OP_LSHIFT 到 OP_RSHIFT 为位操作相关操作码，已禁用
	OP_LSHIFT = 0x98 // 152 - 左移操作，已禁用
	OP_RSHIFT = 0x99 // 153 - 右移操作，已禁用
	// OP_BOOLAND 到 OP_WITHIN 为逻辑操作相关操作码
	OP_BOOLAND            = 0x9a // 154 - 布尔与操作
	OP_BOOLOR             = 0x9b // 155 - 布尔或操作
	OP_NUMEQUAL           = 0x9c // 156 - 数字相等比较
	OP_NUMEQUALVERIFY     = 0x9d // 157 - 数字相等验证
	OP_NUMNOTEQUAL        = 0x9e // 158 - 数字不等比较
	OP_LESSTHAN           = 0x9f // 159 - 小于比较
	OP_GREATERTHAN        = 0xa0 // 160 - 大于比较
	OP_LESSTHANOREQUAL    = 0xa1 // 161 - 小于等于比较
	OP_GREATERTHANOREQUAL = 0xa2 // 162 - 大于等于比较
	OP_MIN                = 0xa3 // 163 - 取最小值
	OP_MAX                = 0xa4 // 164 - 取最大值
	OP_WITHIN             = 0xa5 // 165 - 检查值是否在指定的范围内
	// OP_RIPEMD160 到 OP_HASH256 为哈希操作相关操作码
	OP_RIPEMD160           = 0xa6 // 166 - 对栈顶元素进行RIPEMD-160哈希
	OP_SHA1                = 0xa7 // 167 - 对栈顶元素进行SHA-1哈希
	OP_SHA256              = 0xa8 // 168 - 对栈顶元素进行SHA-256哈希
	OP_HASH160             = 0xa9 // 169 - 对栈顶元素进行SHA-256然后RIPEMD-160哈希
	OP_HASH256             = 0xaa // 170 - 对栈顶元素进行两次SHA-256哈希
	OP_CODESEPARATOR       = 0xab // 171 - 更改签名验证操作的起始位置
	OP_CHECKSIG            = 0xac // 172 - 验证交易签名
	OP_CHECKSIGVERIFY      = 0xad // 173 - 验证签名并验证结果
	OP_CHECKMULTISIG       = 0xae // 174 - 验证多重签名
	OP_CHECKMULTISIGVERIFY = 0xaf // 175 - 验证多重签名并验证结果
	// OP_NOP1 到 OP_NOP10 为NOP操作码，用于占位或未来升级
	OP_NOP1                = 0xb0 // 176
	OP_NOP2                = 0xb1 // 177
	OP_CHECKLOCKTIMEVERIFY = 0xb1 // 177 - AKA OP_NOP2
	OP_NOP3                = 0xb2 // 178
	OP_CHECKSEQUENCEVERIFY = 0xb2 // 178 - AKA OP_NOP3
	OP_NOP4                = 0xb3 // 179
	OP_NOP5                = 0xb4 // 180
	OP_NOP6                = 0xb5 // 181
	OP_NOP7                = 0xb6 // 182
	OP_NOP8                = 0xb7 // 183
	OP_NOP9                = 0xb8 // 184
	OP_NOP10               = 0xb9 // 185
	OP_CHECKSIGADD         = 0xba // 186 - 添加签名操作
	// OP_UNKNOWN187 到 OP_UNKNOWN249 为未知或未使用的操作码
	OP_UNKNOWN187 = 0xbb // 187
	OP_UNKNOWN188 = 0xbc // 188
	OP_UNKNOWN189 = 0xbd // 189
	OP_UNKNOWN190 = 0xbe // 190
	OP_UNKNOWN191 = 0xbf // 191
	OP_UNKNOWN192 = 0xc0 // 192
	OP_UNKNOWN193 = 0xc1 // 193
	OP_UNKNOWN194 = 0xc2 // 194
	OP_UNKNOWN195 = 0xc3 // 195
	OP_UNKNOWN196 = 0xc4 // 196
	OP_UNKNOWN197 = 0xc5 // 197
	OP_UNKNOWN198 = 0xc6 // 198
	OP_UNKNOWN199 = 0xc7 // 199
	OP_UNKNOWN200 = 0xc8 // 200
	OP_UNKNOWN201 = 0xc9 // 201
	OP_UNKNOWN202 = 0xca // 202
	OP_UNKNOWN203 = 0xcb // 203
	OP_UNKNOWN204 = 0xcc // 204
	OP_UNKNOWN205 = 0xcd // 205
	OP_UNKNOWN206 = 0xce // 206
	OP_UNKNOWN207 = 0xcf // 207
	OP_UNKNOWN208 = 0xd0 // 208
	OP_UNKNOWN209 = 0xd1 // 209
	OP_UNKNOWN210 = 0xd2 // 210
	OP_UNKNOWN211 = 0xd3 // 211
	OP_UNKNOWN212 = 0xd4 // 212
	OP_UNKNOWN213 = 0xd5 // 213
	OP_UNKNOWN214 = 0xd6 // 214
	OP_UNKNOWN215 = 0xd7 // 215
	OP_UNKNOWN216 = 0xd8 // 216
	OP_UNKNOWN217 = 0xd9 // 217
	OP_UNKNOWN218 = 0xda // 218
	OP_UNKNOWN219 = 0xdb // 219
	OP_UNKNOWN220 = 0xdc // 220
	OP_UNKNOWN221 = 0xdd // 221
	OP_UNKNOWN222 = 0xde // 222
	OP_UNKNOWN223 = 0xdf // 223
	OP_UNKNOWN224 = 0xe0 // 224
	OP_UNKNOWN225 = 0xe1 // 225
	OP_UNKNOWN226 = 0xe2 // 226
	OP_UNKNOWN227 = 0xe3 // 227
	OP_UNKNOWN228 = 0xe4 // 228
	OP_UNKNOWN229 = 0xe5 // 229
	OP_UNKNOWN230 = 0xe6 // 230
	OP_UNKNOWN231 = 0xe7 // 231
	OP_UNKNOWN232 = 0xe8 // 232
	OP_UNKNOWN233 = 0xe9 // 233
	OP_UNKNOWN234 = 0xea // 234
	OP_UNKNOWN235 = 0xeb // 235
	OP_UNKNOWN236 = 0xec // 236
	OP_UNKNOWN237 = 0xed // 237
	OP_UNKNOWN238 = 0xee // 238
	OP_UNKNOWN239 = 0xef // 239
	OP_UNKNOWN240 = 0xf0 // 240
	OP_UNKNOWN241 = 0xf1 // 241
	OP_UNKNOWN242 = 0xf2 // 242
	OP_UNKNOWN243 = 0xf3 // 243
	OP_UNKNOWN244 = 0xf4 // 244
	OP_UNKNOWN245 = 0xf5 // 245
	OP_UNKNOWN246 = 0xf6 // 246
	OP_UNKNOWN247 = 0xf7 // 247
	OP_UNKNOWN248 = 0xf8 // 248
	OP_UNKNOWN249 = 0xf9 // 249
	// OP_SMALLINTEGER 到 OP_INVALIDOPCODE 为比特币核心内部使用的操作码
	OP_SMALLINTEGER  = 0xfa // 250 - 比特币核心内部使用
	OP_PUBKEYS       = 0xfb // 251 - bitcoin core internal
	OP_UNKNOWN252    = 0xfc // 252
	OP_PUBKEYHASH    = 0xfd // 253 - bitcoin core internal
	OP_PUBKEY        = 0xfe // 254 - bitcoin core internal
	OP_INVALIDOPCODE = 0xff // 255 - bitcoin core internal
)

// Conditional 执行常数。
const (
	OpCondFalse = 0
	OpCondTrue  = 1
	OpCondSkip  = 2
)

// opcodeArray 保存有关所有可能的操作码的详细信息，例如操作码和任何关联数据应占用多少字节、其人类可读的名称以及处理程序函数。
var opcodeArray = [256]opcode{
	// 数据推送操作码。
	OP_FALSE:     {OP_FALSE, "OP_0", 1, opcodeFalse},
	OP_DATA_1:    {OP_DATA_1, "OP_DATA_1", 2, opcodePushData},
	OP_DATA_2:    {OP_DATA_2, "OP_DATA_2", 3, opcodePushData},
	OP_DATA_3:    {OP_DATA_3, "OP_DATA_3", 4, opcodePushData},
	OP_DATA_4:    {OP_DATA_4, "OP_DATA_4", 5, opcodePushData},
	OP_DATA_5:    {OP_DATA_5, "OP_DATA_5", 6, opcodePushData},
	OP_DATA_6:    {OP_DATA_6, "OP_DATA_6", 7, opcodePushData},
	OP_DATA_7:    {OP_DATA_7, "OP_DATA_7", 8, opcodePushData},
	OP_DATA_8:    {OP_DATA_8, "OP_DATA_8", 9, opcodePushData},
	OP_DATA_9:    {OP_DATA_9, "OP_DATA_9", 10, opcodePushData},
	OP_DATA_10:   {OP_DATA_10, "OP_DATA_10", 11, opcodePushData},
	OP_DATA_11:   {OP_DATA_11, "OP_DATA_11", 12, opcodePushData},
	OP_DATA_12:   {OP_DATA_12, "OP_DATA_12", 13, opcodePushData},
	OP_DATA_13:   {OP_DATA_13, "OP_DATA_13", 14, opcodePushData},
	OP_DATA_14:   {OP_DATA_14, "OP_DATA_14", 15, opcodePushData},
	OP_DATA_15:   {OP_DATA_15, "OP_DATA_15", 16, opcodePushData},
	OP_DATA_16:   {OP_DATA_16, "OP_DATA_16", 17, opcodePushData},
	OP_DATA_17:   {OP_DATA_17, "OP_DATA_17", 18, opcodePushData},
	OP_DATA_18:   {OP_DATA_18, "OP_DATA_18", 19, opcodePushData},
	OP_DATA_19:   {OP_DATA_19, "OP_DATA_19", 20, opcodePushData},
	OP_DATA_20:   {OP_DATA_20, "OP_DATA_20", 21, opcodePushData},
	OP_DATA_21:   {OP_DATA_21, "OP_DATA_21", 22, opcodePushData},
	OP_DATA_22:   {OP_DATA_22, "OP_DATA_22", 23, opcodePushData},
	OP_DATA_23:   {OP_DATA_23, "OP_DATA_23", 24, opcodePushData},
	OP_DATA_24:   {OP_DATA_24, "OP_DATA_24", 25, opcodePushData},
	OP_DATA_25:   {OP_DATA_25, "OP_DATA_25", 26, opcodePushData},
	OP_DATA_26:   {OP_DATA_26, "OP_DATA_26", 27, opcodePushData},
	OP_DATA_27:   {OP_DATA_27, "OP_DATA_27", 28, opcodePushData},
	OP_DATA_28:   {OP_DATA_28, "OP_DATA_28", 29, opcodePushData},
	OP_DATA_29:   {OP_DATA_29, "OP_DATA_29", 30, opcodePushData},
	OP_DATA_30:   {OP_DATA_30, "OP_DATA_30", 31, opcodePushData},
	OP_DATA_31:   {OP_DATA_31, "OP_DATA_31", 32, opcodePushData},
	OP_DATA_32:   {OP_DATA_32, "OP_DATA_32", 33, opcodePushData},
	OP_DATA_33:   {OP_DATA_33, "OP_DATA_33", 34, opcodePushData},
	OP_DATA_34:   {OP_DATA_34, "OP_DATA_34", 35, opcodePushData},
	OP_DATA_35:   {OP_DATA_35, "OP_DATA_35", 36, opcodePushData},
	OP_DATA_36:   {OP_DATA_36, "OP_DATA_36", 37, opcodePushData},
	OP_DATA_37:   {OP_DATA_37, "OP_DATA_37", 38, opcodePushData},
	OP_DATA_38:   {OP_DATA_38, "OP_DATA_38", 39, opcodePushData},
	OP_DATA_39:   {OP_DATA_39, "OP_DATA_39", 40, opcodePushData},
	OP_DATA_40:   {OP_DATA_40, "OP_DATA_40", 41, opcodePushData},
	OP_DATA_41:   {OP_DATA_41, "OP_DATA_41", 42, opcodePushData},
	OP_DATA_42:   {OP_DATA_42, "OP_DATA_42", 43, opcodePushData},
	OP_DATA_43:   {OP_DATA_43, "OP_DATA_43", 44, opcodePushData},
	OP_DATA_44:   {OP_DATA_44, "OP_DATA_44", 45, opcodePushData},
	OP_DATA_45:   {OP_DATA_45, "OP_DATA_45", 46, opcodePushData},
	OP_DATA_46:   {OP_DATA_46, "OP_DATA_46", 47, opcodePushData},
	OP_DATA_47:   {OP_DATA_47, "OP_DATA_47", 48, opcodePushData},
	OP_DATA_48:   {OP_DATA_48, "OP_DATA_48", 49, opcodePushData},
	OP_DATA_49:   {OP_DATA_49, "OP_DATA_49", 50, opcodePushData},
	OP_DATA_50:   {OP_DATA_50, "OP_DATA_50", 51, opcodePushData},
	OP_DATA_51:   {OP_DATA_51, "OP_DATA_51", 52, opcodePushData},
	OP_DATA_52:   {OP_DATA_52, "OP_DATA_52", 53, opcodePushData},
	OP_DATA_53:   {OP_DATA_53, "OP_DATA_53", 54, opcodePushData},
	OP_DATA_54:   {OP_DATA_54, "OP_DATA_54", 55, opcodePushData},
	OP_DATA_55:   {OP_DATA_55, "OP_DATA_55", 56, opcodePushData},
	OP_DATA_56:   {OP_DATA_56, "OP_DATA_56", 57, opcodePushData},
	OP_DATA_57:   {OP_DATA_57, "OP_DATA_57", 58, opcodePushData},
	OP_DATA_58:   {OP_DATA_58, "OP_DATA_58", 59, opcodePushData},
	OP_DATA_59:   {OP_DATA_59, "OP_DATA_59", 60, opcodePushData},
	OP_DATA_60:   {OP_DATA_60, "OP_DATA_60", 61, opcodePushData},
	OP_DATA_61:   {OP_DATA_61, "OP_DATA_61", 62, opcodePushData},
	OP_DATA_62:   {OP_DATA_62, "OP_DATA_62", 63, opcodePushData},
	OP_DATA_63:   {OP_DATA_63, "OP_DATA_63", 64, opcodePushData},
	OP_DATA_64:   {OP_DATA_64, "OP_DATA_64", 65, opcodePushData},
	OP_DATA_65:   {OP_DATA_65, "OP_DATA_65", 66, opcodePushData},
	OP_DATA_66:   {OP_DATA_66, "OP_DATA_66", 67, opcodePushData},
	OP_DATA_67:   {OP_DATA_67, "OP_DATA_67", 68, opcodePushData},
	OP_DATA_68:   {OP_DATA_68, "OP_DATA_68", 69, opcodePushData},
	OP_DATA_69:   {OP_DATA_69, "OP_DATA_69", 70, opcodePushData},
	OP_DATA_70:   {OP_DATA_70, "OP_DATA_70", 71, opcodePushData},
	OP_DATA_71:   {OP_DATA_71, "OP_DATA_71", 72, opcodePushData},
	OP_DATA_72:   {OP_DATA_72, "OP_DATA_72", 73, opcodePushData},
	OP_DATA_73:   {OP_DATA_73, "OP_DATA_73", 74, opcodePushData},
	OP_DATA_74:   {OP_DATA_74, "OP_DATA_74", 75, opcodePushData},
	OP_DATA_75:   {OP_DATA_75, "OP_DATA_75", 76, opcodePushData},
	OP_PUSHDATA1: {OP_PUSHDATA1, "OP_PUSHDATA1", -1, opcodePushData},
	OP_PUSHDATA2: {OP_PUSHDATA2, "OP_PUSHDATA2", -2, opcodePushData},
	OP_PUSHDATA4: {OP_PUSHDATA4, "OP_PUSHDATA4", -4, opcodePushData},
	OP_1NEGATE:   {OP_1NEGATE, "OP_1NEGATE", 1, opcode1Negate},
	OP_RESERVED:  {OP_RESERVED, "OP_RESERVED", 1, opcodeReserved},
	OP_TRUE:      {OP_TRUE, "OP_1", 1, opcodeN},
	OP_2:         {OP_2, "OP_2", 1, opcodeN},
	OP_3:         {OP_3, "OP_3", 1, opcodeN},
	OP_4:         {OP_4, "OP_4", 1, opcodeN},
	OP_5:         {OP_5, "OP_5", 1, opcodeN},
	OP_6:         {OP_6, "OP_6", 1, opcodeN},
	OP_7:         {OP_7, "OP_7", 1, opcodeN},
	OP_8:         {OP_8, "OP_8", 1, opcodeN},
	OP_9:         {OP_9, "OP_9", 1, opcodeN},
	OP_10:        {OP_10, "OP_10", 1, opcodeN},
	OP_11:        {OP_11, "OP_11", 1, opcodeN},
	OP_12:        {OP_12, "OP_12", 1, opcodeN},
	OP_13:        {OP_13, "OP_13", 1, opcodeN},
	OP_14:        {OP_14, "OP_14", 1, opcodeN},
	OP_15:        {OP_15, "OP_15", 1, opcodeN},
	OP_16:        {OP_16, "OP_16", 1, opcodeN},

	// 控制操作码。
	OP_NOP:                 {OP_NOP, "OP_NOP", 1, opcodeNop},
	OP_VER:                 {OP_VER, "OP_VER", 1, opcodeReserved},
	OP_IF:                  {OP_IF, "OP_IF", 1, opcodeIf},
	OP_NOTIF:               {OP_NOTIF, "OP_NOTIF", 1, opcodeNotIf},
	OP_VERIF:               {OP_VERIF, "OP_VERIF", 1, opcodeReserved},
	OP_VERNOTIF:            {OP_VERNOTIF, "OP_VERNOTIF", 1, opcodeReserved},
	OP_ELSE:                {OP_ELSE, "OP_ELSE", 1, opcodeElse},
	OP_ENDIF:               {OP_ENDIF, "OP_ENDIF", 1, opcodeEndif},
	OP_VERIFY:              {OP_VERIFY, "OP_VERIFY", 1, opcodeVerify},
	OP_RETURN:              {OP_RETURN, "OP_RETURN", 1, opcodeReturn},
	OP_CHECKLOCKTIMEVERIFY: {OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY", 1, opcodeCheckLockTimeVerify},
	OP_CHECKSEQUENCEVERIFY: {OP_CHECKSEQUENCEVERIFY, "OP_CHECKSEQUENCEVERIFY", 1, opcodeCheckSequenceVerify},

	// 堆栈操作码。
	OP_TOALTSTACK:   {OP_TOALTSTACK, "OP_TOALTSTACK", 1, opcodeToAltStack},
	OP_FROMALTSTACK: {OP_FROMALTSTACK, "OP_FROMALTSTACK", 1, opcodeFromAltStack},
	OP_2DROP:        {OP_2DROP, "OP_2DROP", 1, opcode2Drop},
	OP_2DUP:         {OP_2DUP, "OP_2DUP", 1, opcode2Dup},
	OP_3DUP:         {OP_3DUP, "OP_3DUP", 1, opcode3Dup},
	OP_2OVER:        {OP_2OVER, "OP_2OVER", 1, opcode2Over},
	OP_2ROT:         {OP_2ROT, "OP_2ROT", 1, opcode2Rot},
	OP_2SWAP:        {OP_2SWAP, "OP_2SWAP", 1, opcode2Swap},
	OP_IFDUP:        {OP_IFDUP, "OP_IFDUP", 1, opcodeIfDup},
	OP_DEPTH:        {OP_DEPTH, "OP_DEPTH", 1, opcodeDepth},
	OP_DROP:         {OP_DROP, "OP_DROP", 1, opcodeDrop},
	OP_DUP:          {OP_DUP, "OP_DUP", 1, opcodeDup},
	OP_NIP:          {OP_NIP, "OP_NIP", 1, opcodeNip},
	OP_OVER:         {OP_OVER, "OP_OVER", 1, opcodeOver},
	OP_PICK:         {OP_PICK, "OP_PICK", 1, opcodePick},
	OP_ROLL:         {OP_ROLL, "OP_ROLL", 1, opcodeRoll},
	OP_ROT:          {OP_ROT, "OP_ROT", 1, opcodeRot},
	OP_SWAP:         {OP_SWAP, "OP_SWAP", 1, opcodeSwap},
	OP_TUCK:         {OP_TUCK, "OP_TUCK", 1, opcodeTuck},

	// 拼接操作码。
	OP_CAT:    {OP_CAT, "OP_CAT", 1, opcodeDisabled},
	OP_SUBSTR: {OP_SUBSTR, "OP_SUBSTR", 1, opcodeDisabled},
	OP_LEFT:   {OP_LEFT, "OP_LEFT", 1, opcodeDisabled},
	OP_RIGHT:  {OP_RIGHT, "OP_RIGHT", 1, opcodeDisabled},
	OP_SIZE:   {OP_SIZE, "OP_SIZE", 1, opcodeSize},

	// 按位逻辑操作码。
	OP_INVERT:      {OP_INVERT, "OP_INVERT", 1, opcodeDisabled},
	OP_AND:         {OP_AND, "OP_AND", 1, opcodeDisabled},
	OP_OR:          {OP_OR, "OP_OR", 1, opcodeDisabled},
	OP_XOR:         {OP_XOR, "OP_XOR", 1, opcodeDisabled},
	OP_EQUAL:       {OP_EQUAL, "OP_EQUAL", 1, opcodeEqual},
	OP_EQUALVERIFY: {OP_EQUALVERIFY, "OP_EQUALVERIFY", 1, opcodeEqualVerify},
	OP_RESERVED1:   {OP_RESERVED1, "OP_RESERVED1", 1, opcodeReserved},
	OP_RESERVED2:   {OP_RESERVED2, "OP_RESERVED2", 1, opcodeReserved},

	// 数字相关的操作码。
	OP_1ADD:               {OP_1ADD, "OP_1ADD", 1, opcode1Add},
	OP_1SUB:               {OP_1SUB, "OP_1SUB", 1, opcode1Sub},
	OP_2MUL:               {OP_2MUL, "OP_2MUL", 1, opcodeDisabled},
	OP_2DIV:               {OP_2DIV, "OP_2DIV", 1, opcodeDisabled},
	OP_NEGATE:             {OP_NEGATE, "OP_NEGATE", 1, opcodeNegate},
	OP_ABS:                {OP_ABS, "OP_ABS", 1, opcodeAbs},
	OP_NOT:                {OP_NOT, "OP_NOT", 1, opcodeNot},
	OP_0NOTEQUAL:          {OP_0NOTEQUAL, "OP_0NOTEQUAL", 1, opcode0NotEqual},
	OP_ADD:                {OP_ADD, "OP_ADD", 1, opcodeAdd},
	OP_SUB:                {OP_SUB, "OP_SUB", 1, opcodeSub},
	OP_MUL:                {OP_MUL, "OP_MUL", 1, opcodeDisabled},
	OP_DIV:                {OP_DIV, "OP_DIV", 1, opcodeDisabled},
	OP_MOD:                {OP_MOD, "OP_MOD", 1, opcodeDisabled},
	OP_LSHIFT:             {OP_LSHIFT, "OP_LSHIFT", 1, opcodeDisabled},
	OP_RSHIFT:             {OP_RSHIFT, "OP_RSHIFT", 1, opcodeDisabled},
	OP_BOOLAND:            {OP_BOOLAND, "OP_BOOLAND", 1, opcodeBoolAnd},
	OP_BOOLOR:             {OP_BOOLOR, "OP_BOOLOR", 1, opcodeBoolOr},
	OP_NUMEQUAL:           {OP_NUMEQUAL, "OP_NUMEQUAL", 1, opcodeNumEqual},
	OP_NUMEQUALVERIFY:     {OP_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY", 1, opcodeNumEqualVerify},
	OP_NUMNOTEQUAL:        {OP_NUMNOTEQUAL, "OP_NUMNOTEQUAL", 1, opcodeNumNotEqual},
	OP_LESSTHAN:           {OP_LESSTHAN, "OP_LESSTHAN", 1, opcodeLessThan},
	OP_GREATERTHAN:        {OP_GREATERTHAN, "OP_GREATERTHAN", 1, opcodeGreaterThan},
	OP_LESSTHANOREQUAL:    {OP_LESSTHANOREQUAL, "OP_LESSTHANOREQUAL", 1, opcodeLessThanOrEqual},
	OP_GREATERTHANOREQUAL: {OP_GREATERTHANOREQUAL, "OP_GREATERTHANOREQUAL", 1, opcodeGreaterThanOrEqual},
	OP_MIN:                {OP_MIN, "OP_MIN", 1, opcodeMin},
	OP_MAX:                {OP_MAX, "OP_MAX", 1, opcodeMax},
	OP_WITHIN:             {OP_WITHIN, "OP_WITHIN", 1, opcodeWithin},

	// 加密操作码。
	OP_RIPEMD160:           {OP_RIPEMD160, "OP_RIPEMD160", 1, opcodeRipemd160},
	OP_SHA1:                {OP_SHA1, "OP_SHA1", 1, opcodeSha1},
	OP_SHA256:              {OP_SHA256, "OP_SHA256", 1, opcodeSha256},
	OP_HASH160:             {OP_HASH160, "OP_HASH160", 1, opcodeHash160},
	OP_HASH256:             {OP_HASH256, "OP_HASH256", 1, opcodeHash256},
	OP_CODESEPARATOR:       {OP_CODESEPARATOR, "OP_CODESEPARATOR", 1, opcodeCodeSeparator},
	OP_CHECKSIG:            {OP_CHECKSIG, "OP_CHECKSIG", 1, opcodeCheckSig},
	OP_CHECKSIGVERIFY:      {OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY", 1, opcodeCheckSigVerify},
	OP_CHECKMULTISIG:       {OP_CHECKMULTISIG, "OP_CHECKMULTISIG", 1, opcodeCheckMultiSig},
	OP_CHECKMULTISIGVERIFY: {OP_CHECKMULTISIGVERIFY, "OP_CHECKMULTISIGVERIFY", 1, opcodeCheckMultiSigVerify},
	OP_CHECKSIGADD:         {OP_CHECKSIGADD, "OP_CHECKSIGADD", 1, opcodeCheckSigAdd},

	// 保留的操作码。
	OP_NOP1:  {OP_NOP1, "OP_NOP1", 1, opcodeNop},
	OP_NOP4:  {OP_NOP4, "OP_NOP4", 1, opcodeNop},
	OP_NOP5:  {OP_NOP5, "OP_NOP5", 1, opcodeNop},
	OP_NOP6:  {OP_NOP6, "OP_NOP6", 1, opcodeNop},
	OP_NOP7:  {OP_NOP7, "OP_NOP7", 1, opcodeNop},
	OP_NOP8:  {OP_NOP8, "OP_NOP8", 1, opcodeNop},
	OP_NOP9:  {OP_NOP9, "OP_NOP9", 1, opcodeNop},
	OP_NOP10: {OP_NOP10, "OP_NOP10", 1, opcodeNop},

	// 未定义的操作码。
	OP_UNKNOWN187: {OP_UNKNOWN187, "OP_UNKNOWN187", 1, opcodeInvalid},
	OP_UNKNOWN188: {OP_UNKNOWN188, "OP_UNKNOWN188", 1, opcodeInvalid},
	OP_UNKNOWN189: {OP_UNKNOWN189, "OP_UNKNOWN189", 1, opcodeInvalid},
	OP_UNKNOWN190: {OP_UNKNOWN190, "OP_UNKNOWN190", 1, opcodeInvalid},
	OP_UNKNOWN191: {OP_UNKNOWN191, "OP_UNKNOWN191", 1, opcodeInvalid},
	OP_UNKNOWN192: {OP_UNKNOWN192, "OP_UNKNOWN192", 1, opcodeInvalid},
	OP_UNKNOWN193: {OP_UNKNOWN193, "OP_UNKNOWN193", 1, opcodeInvalid},
	OP_UNKNOWN194: {OP_UNKNOWN194, "OP_UNKNOWN194", 1, opcodeInvalid},
	OP_UNKNOWN195: {OP_UNKNOWN195, "OP_UNKNOWN195", 1, opcodeInvalid},
	OP_UNKNOWN196: {OP_UNKNOWN196, "OP_UNKNOWN196", 1, opcodeInvalid},
	OP_UNKNOWN197: {OP_UNKNOWN197, "OP_UNKNOWN197", 1, opcodeInvalid},
	OP_UNKNOWN198: {OP_UNKNOWN198, "OP_UNKNOWN198", 1, opcodeInvalid},
	OP_UNKNOWN199: {OP_UNKNOWN199, "OP_UNKNOWN199", 1, opcodeInvalid},
	OP_UNKNOWN200: {OP_UNKNOWN200, "OP_UNKNOWN200", 1, opcodeInvalid},
	OP_UNKNOWN201: {OP_UNKNOWN201, "OP_UNKNOWN201", 1, opcodeInvalid},
	OP_UNKNOWN202: {OP_UNKNOWN202, "OP_UNKNOWN202", 1, opcodeInvalid},
	OP_UNKNOWN203: {OP_UNKNOWN203, "OP_UNKNOWN203", 1, opcodeInvalid},
	OP_UNKNOWN204: {OP_UNKNOWN204, "OP_UNKNOWN204", 1, opcodeInvalid},
	OP_UNKNOWN205: {OP_UNKNOWN205, "OP_UNKNOWN205", 1, opcodeInvalid},
	OP_UNKNOWN206: {OP_UNKNOWN206, "OP_UNKNOWN206", 1, opcodeInvalid},
	OP_UNKNOWN207: {OP_UNKNOWN207, "OP_UNKNOWN207", 1, opcodeInvalid},
	OP_UNKNOWN208: {OP_UNKNOWN208, "OP_UNKNOWN208", 1, opcodeInvalid},
	OP_UNKNOWN209: {OP_UNKNOWN209, "OP_UNKNOWN209", 1, opcodeInvalid},
	OP_UNKNOWN210: {OP_UNKNOWN210, "OP_UNKNOWN210", 1, opcodeInvalid},
	OP_UNKNOWN211: {OP_UNKNOWN211, "OP_UNKNOWN211", 1, opcodeInvalid},
	OP_UNKNOWN212: {OP_UNKNOWN212, "OP_UNKNOWN212", 1, opcodeInvalid},
	OP_UNKNOWN213: {OP_UNKNOWN213, "OP_UNKNOWN213", 1, opcodeInvalid},
	OP_UNKNOWN214: {OP_UNKNOWN214, "OP_UNKNOWN214", 1, opcodeInvalid},
	OP_UNKNOWN215: {OP_UNKNOWN215, "OP_UNKNOWN215", 1, opcodeInvalid},
	OP_UNKNOWN216: {OP_UNKNOWN216, "OP_UNKNOWN216", 1, opcodeInvalid},
	OP_UNKNOWN217: {OP_UNKNOWN217, "OP_UNKNOWN217", 1, opcodeInvalid},
	OP_UNKNOWN218: {OP_UNKNOWN218, "OP_UNKNOWN218", 1, opcodeInvalid},
	OP_UNKNOWN219: {OP_UNKNOWN219, "OP_UNKNOWN219", 1, opcodeInvalid},
	OP_UNKNOWN220: {OP_UNKNOWN220, "OP_UNKNOWN220", 1, opcodeInvalid},
	OP_UNKNOWN221: {OP_UNKNOWN221, "OP_UNKNOWN221", 1, opcodeInvalid},
	OP_UNKNOWN222: {OP_UNKNOWN222, "OP_UNKNOWN222", 1, opcodeInvalid},
	OP_UNKNOWN223: {OP_UNKNOWN223, "OP_UNKNOWN223", 1, opcodeInvalid},
	OP_UNKNOWN224: {OP_UNKNOWN224, "OP_UNKNOWN224", 1, opcodeInvalid},
	OP_UNKNOWN225: {OP_UNKNOWN225, "OP_UNKNOWN225", 1, opcodeInvalid},
	OP_UNKNOWN226: {OP_UNKNOWN226, "OP_UNKNOWN226", 1, opcodeInvalid},
	OP_UNKNOWN227: {OP_UNKNOWN227, "OP_UNKNOWN227", 1, opcodeInvalid},
	OP_UNKNOWN228: {OP_UNKNOWN228, "OP_UNKNOWN228", 1, opcodeInvalid},
	OP_UNKNOWN229: {OP_UNKNOWN229, "OP_UNKNOWN229", 1, opcodeInvalid},
	OP_UNKNOWN230: {OP_UNKNOWN230, "OP_UNKNOWN230", 1, opcodeInvalid},
	OP_UNKNOWN231: {OP_UNKNOWN231, "OP_UNKNOWN231", 1, opcodeInvalid},
	OP_UNKNOWN232: {OP_UNKNOWN232, "OP_UNKNOWN232", 1, opcodeInvalid},
	OP_UNKNOWN233: {OP_UNKNOWN233, "OP_UNKNOWN233", 1, opcodeInvalid},
	OP_UNKNOWN234: {OP_UNKNOWN234, "OP_UNKNOWN234", 1, opcodeInvalid},
	OP_UNKNOWN235: {OP_UNKNOWN235, "OP_UNKNOWN235", 1, opcodeInvalid},
	OP_UNKNOWN236: {OP_UNKNOWN236, "OP_UNKNOWN236", 1, opcodeInvalid},
	OP_UNKNOWN237: {OP_UNKNOWN237, "OP_UNKNOWN237", 1, opcodeInvalid},
	OP_UNKNOWN238: {OP_UNKNOWN238, "OP_UNKNOWN238", 1, opcodeInvalid},
	OP_UNKNOWN239: {OP_UNKNOWN239, "OP_UNKNOWN239", 1, opcodeInvalid},
	OP_UNKNOWN240: {OP_UNKNOWN240, "OP_UNKNOWN240", 1, opcodeInvalid},
	OP_UNKNOWN241: {OP_UNKNOWN241, "OP_UNKNOWN241", 1, opcodeInvalid},
	OP_UNKNOWN242: {OP_UNKNOWN242, "OP_UNKNOWN242", 1, opcodeInvalid},
	OP_UNKNOWN243: {OP_UNKNOWN243, "OP_UNKNOWN243", 1, opcodeInvalid},
	OP_UNKNOWN244: {OP_UNKNOWN244, "OP_UNKNOWN244", 1, opcodeInvalid},
	OP_UNKNOWN245: {OP_UNKNOWN245, "OP_UNKNOWN245", 1, opcodeInvalid},
	OP_UNKNOWN246: {OP_UNKNOWN246, "OP_UNKNOWN246", 1, opcodeInvalid},
	OP_UNKNOWN247: {OP_UNKNOWN247, "OP_UNKNOWN247", 1, opcodeInvalid},
	OP_UNKNOWN248: {OP_UNKNOWN248, "OP_UNKNOWN248", 1, opcodeInvalid},
	OP_UNKNOWN249: {OP_UNKNOWN249, "OP_UNKNOWN249", 1, opcodeInvalid},

	// 比特币核心内部使用操作码。 此处定义是为了完整性。
	OP_SMALLINTEGER: {OP_SMALLINTEGER, "OP_SMALLINTEGER", 1, opcodeInvalid},
	OP_PUBKEYS:      {OP_PUBKEYS, "OP_PUBKEYS", 1, opcodeInvalid},
	OP_UNKNOWN252:   {OP_UNKNOWN252, "OP_UNKNOWN252", 1, opcodeInvalid},
	OP_PUBKEYHASH:   {OP_PUBKEYHASH, "OP_PUBKEYHASH", 1, opcodeInvalid},
	OP_PUBKEY:       {OP_PUBKEY, "OP_PUBKEY", 1, opcodeInvalid},

	OP_INVALIDOPCODE: {OP_INVALIDOPCODE, "OP_INVALIDOPCODE", 1, opcodeInvalid},
}

// opcodeOnelineRepls 定义在进行单行反汇编时被替换的操作码名称。 这样做是为了匹配参考实现的输出，同时不更改更好的完整反汇编中的操作码名称。
var opcodeOnelineRepls = map[string]string{
	"OP_1NEGATE": "-1",
	"OP_0":       "0",
	"OP_1":       "1",
	"OP_2":       "2",
	"OP_3":       "3",
	"OP_4":       "4",
	"OP_5":       "5",
	"OP_6":       "6",
	"OP_7":       "7",
	"OP_8":       "8",
	"OP_9":       "9",
	"OP_10":      "10",
	"OP_11":      "11",
	"OP_12":      "12",
	"OP_13":      "13",
	"OP_14":      "14",
	"OP_15":      "15",
	"OP_16":      "16",
}

// successOpcodes 跟踪将被解释为导致执行自动成功的操作码的操作码集。 该映射用于在脚本预处理期间快速查找操作码。
var successOpcodes = map[byte]struct{}{
	OP_RESERVED:     {}, // 80
	OP_VER:          {}, // 98
	OP_CAT:          {}, // 126
	OP_SUBSTR:       {}, // 127
	OP_LEFT:         {}, // 128
	OP_RIGHT:        {}, // 129
	OP_INVERT:       {}, // 131
	OP_AND:          {}, // 132
	OP_OR:           {}, // 133
	OP_XOR:          {}, // 134
	OP_RESERVED1:    {}, // 137
	OP_RESERVED2:    {}, // 138
	OP_2MUL:         {}, // 141
	OP_2DIV:         {}, // 142
	OP_MUL:          {}, // 149
	OP_DIV:          {}, // 150
	OP_MOD:          {}, // 151
	OP_LSHIFT:       {}, // 152
	OP_RSHIFT:       {}, // 153
	OP_UNKNOWN187:   {}, // 187
	OP_UNKNOWN188:   {}, // 188
	OP_UNKNOWN189:   {}, // 189
	OP_UNKNOWN190:   {}, // 190
	OP_UNKNOWN191:   {}, // 191
	OP_UNKNOWN192:   {}, // 192
	OP_UNKNOWN193:   {}, // 193
	OP_UNKNOWN194:   {}, // 194
	OP_UNKNOWN195:   {}, // 195
	OP_UNKNOWN196:   {}, // 196
	OP_UNKNOWN197:   {}, // 197
	OP_UNKNOWN198:   {}, // 198
	OP_UNKNOWN199:   {}, // 199
	OP_UNKNOWN200:   {}, // 200
	OP_UNKNOWN201:   {}, // 201
	OP_UNKNOWN202:   {}, // 202
	OP_UNKNOWN203:   {}, // 203
	OP_UNKNOWN204:   {}, // 204
	OP_UNKNOWN205:   {}, // 205
	OP_UNKNOWN206:   {}, // 206
	OP_UNKNOWN207:   {}, // 207
	OP_UNKNOWN208:   {}, // 208
	OP_UNKNOWN209:   {}, // 209
	OP_UNKNOWN210:   {}, // 210
	OP_UNKNOWN211:   {}, // 211
	OP_UNKNOWN212:   {}, // 212
	OP_UNKNOWN213:   {}, // 213
	OP_UNKNOWN214:   {}, // 214
	OP_UNKNOWN215:   {}, // 215
	OP_UNKNOWN216:   {}, // 216
	OP_UNKNOWN217:   {}, // 217
	OP_UNKNOWN218:   {}, // 218
	OP_UNKNOWN219:   {}, // 219
	OP_UNKNOWN220:   {}, // 220
	OP_UNKNOWN221:   {}, // 221
	OP_UNKNOWN222:   {}, // 222
	OP_UNKNOWN223:   {}, // 223
	OP_UNKNOWN224:   {}, // 224
	OP_UNKNOWN225:   {}, // 225
	OP_UNKNOWN226:   {}, // 226
	OP_UNKNOWN227:   {}, // 227
	OP_UNKNOWN228:   {}, // 228
	OP_UNKNOWN229:   {}, // 229
	OP_UNKNOWN230:   {}, // 230
	OP_UNKNOWN231:   {}, // 231
	OP_UNKNOWN232:   {}, // 232
	OP_UNKNOWN233:   {}, // 233
	OP_UNKNOWN234:   {}, // 234
	OP_UNKNOWN235:   {}, // 235
	OP_UNKNOWN236:   {}, // 236
	OP_UNKNOWN237:   {}, // 237
	OP_UNKNOWN238:   {}, // 238
	OP_UNKNOWN239:   {}, // 239
	OP_UNKNOWN240:   {}, // 240
	OP_UNKNOWN241:   {}, // 241
	OP_UNKNOWN242:   {}, // 242
	OP_UNKNOWN243:   {}, // 243
	OP_UNKNOWN244:   {}, // 244
	OP_UNKNOWN245:   {}, // 245
	OP_UNKNOWN246:   {}, // 246
	OP_UNKNOWN247:   {}, // 247
	OP_UNKNOWN248:   {}, // 248
	OP_UNKNOWN249:   {}, // 249
	OP_SMALLINTEGER: {}, // 250
	OP_PUBKEYS:      {}, // 251
	OP_UNKNOWN252:   {}, // 252
	OP_PUBKEYHASH:   {}, // 253
	OP_PUBKEY:       {}, // 254
}

// disasmOpcode 将所提供的操作码和数据的人类可读反汇编写入所提供的缓冲区中。
// 紧凑标志指示反汇编应该打印更紧凑的数据携带和小整数操作码表示。
// 例如，OP_0 到 OP_16 被替换为数值，并且数据推送仅打印为数据的十六进制表示形式，而不是包括指定要推送的数据量的操作码。
func disasmOpcode(buf *strings.Builder, op *opcode, data []byte, compact bool) {
	// Replace opcode which represent values (e.g. OP_0 through OP_16 and
	// OP_1NEGATE) with the raw value when performing a compact disassembly.
	opcodeName := op.name
	if compact {
		if replName, ok := opcodeOnelineRepls[opcodeName]; ok {
			opcodeName = replName
		}

		// Either write the human-readable opcode or the parsed data in hex for
		// data-carrying opcodes.
		switch {
		case op.length == 1:
			buf.WriteString(opcodeName)

		default:
			buf.WriteString(hex.EncodeToString(data))
		}

		return
	}

	buf.WriteString(opcodeName)

	switch op.length {
	// Only write the opcode name for non-data push opcodes.
	case 1:
		return

	// Add length for the OP_PUSHDATA# opcodes.
	case -1:
		buf.WriteString(fmt.Sprintf(" 0x%02x", len(data)))
	case -2:
		buf.WriteString(fmt.Sprintf(" 0x%04x", len(data)))
	case -4:
		buf.WriteString(fmt.Sprintf(" 0x%08x", len(data)))
	}

	buf.WriteString(fmt.Sprintf(" 0x%02x", data))
}

// *******************************************
// 操作码实现函数从这里开始。
// *******************************************

// opcodeDisabled 是禁用操作码的通用处理程序。
// 它返回一个适当的错误，指示操作码已禁用。
// 虽然在执行初始解析步骤之前检测脚本是否包含任何禁用的操作码通常更有意义，但共识规则规定，在程序计数器传递禁用的操作码之前，脚本不会失败（即使它们出现在 未执行的分支）。
func opcodeDisabled(op *opcode, data []byte, vm *Engine) error {
	str := fmt.Sprintf("attempt to execute disabled opcode %s", op.name)
	return scriptError(ErrDisabledOpcode, str)
}

// opcodeReserved 是所有保留操作码的通用处理程序。
// 它返回一个适当的错误，指示操作码已被保留。
func opcodeReserved(op *opcode, data []byte, vm *Engine) error {
	str := fmt.Sprintf("attempt to execute reserved opcode %s", op.name)
	return scriptError(ErrReservedOpcode, str)
}

// opcodeInvalid 是所有无效操作码的通用处理程序。
// 它返回一个适当的错误，指示操作码无效。
func opcodeInvalid(op *opcode, data []byte, vm *Engine) error {
	str := fmt.Sprintf("attempt to execute invalid opcode %s", op.name)
	return scriptError(ErrReservedOpcode, str)
}

// opcodeFalse 将一个空数组压入数据栈来表示 false。
// 请注意，当根据数字编码共识规则编码为数字时，0 是一个空数组。
func opcodeFalse(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushByteArray(nil)
	return nil
}

// opcodePushData 是绝大多数将原始数据（字节）推送到数据堆栈的操作码的通用处理程序。
func opcodePushData(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushByteArray(data)
	return nil
}

// opcode1Negate 将编码为数字的 -1 推送到数据堆栈。
func opcode1Negate(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushInt(scriptNum(-1))
	return nil
}

// opcodeN 是小整数数据推送操作码的通用处理程序。 它将操作码表示的数值（从 1 到 16）压入数据堆栈。
func opcodeN(op *opcode, data []byte, vm *Engine) error {
	// The opcodes are all defined consecutively, so the numeric value is
	// the difference.
	vm.dstack.PushInt(scriptNum((op.value - (OP_1 - 1))))
	return nil
}

// opcodeNop 是 NOP 系列操作码的通用处理程序。
// 顾名思义，它通常不执行任何操作，但是，当为选择的操作码设置了阻止使用 NOP 的标志时，它将返回错误。
func opcodeNop(op *opcode, data []byte, vm *Engine) error {
	switch op.value {
	case OP_NOP1, OP_NOP4, OP_NOP5,
		OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10:

		if vm.hasFlag(ScriptDiscourageUpgradableNops) {
			str := fmt.Sprintf("%v reserved for soft-fork "+
				"upgrades", op.name)
			return scriptError(ErrDiscourageUpgradableNOPs, str)
		}
	}
	return nil
}

// 如果设置了特定标志，popIfBool 将在脚本执行期间强制执行“最小 if”策略。
// 如果是这样，为了消除令人讨厌的延展性来源，版本 0 见证程序的后隔离验证，我们现在需要以下内容：对于 OP_IF 和 OP_NOT_IF，顶部堆栈项必须是空字节切片，或 [0x01] 。
// 否则，堆栈顶部的项目将被弹出并解释为布尔值。
func popIfBool(vm *Engine) (bool, error) {
	// When not in witness execution mode, not executing a v0 witness
	// program, or not doing tapscript execution, or the minimal if flag
	// isn't set pop the top stack item as a normal bool.
	switch {
	// Minimal if is always on for taproot execution.
	case vm.isWitnessVersionActive(TaprootWitnessVersion):
		break

	// If this isn't the base segwit version, then we'll coerce the stack
	// element as a bool as normal.
	case !vm.isWitnessVersionActive(BaseSegwitWitnessVersion):
		fallthrough

	// If the minimal if flag isn't set, then we don't need any extra
	// checks here.
	case !vm.hasFlag(ScriptVerifyMinimalIf):
		return vm.dstack.PopBool()
	}

	// At this point, a v0 or v1 witness program is being executed and the
	// minimal if flag is set, so enforce additional constraints on the top
	// stack item.
	so, err := vm.dstack.PopByteArray()
	if err != nil {
		return false, err
	}

	// The top element MUST have a length of at least one.
	if len(so) > 1 {
		str := fmt.Sprintf("minimal if is active, top element MUST "+
			"have a length of at least, instead length is %v",
			len(so))
		return false, scriptError(ErrMinimalIf, str)
	}

	// Additionally, if the length is one, then the value MUST be 0x01.
	if len(so) == 1 && so[0] != 0x01 {
		str := fmt.Sprintf("minimal if is active, top stack item MUST "+
			"be an empty byte array or 0x01, is instead: %v",
			so[0])
		return false, scriptError(ErrMinimalIf, str)
	}

	return asBool(so), nil
}

// opcodeIf 将数据堆栈的顶部项目视为布尔值并将其删除。
//
// 根据布尔值是否为 true 以及该 if 是否位于执行分支上，将适当的条目添加到条件堆栈中，以便根据条件逻辑正确执行进一步的操作码。
// 当布尔值为 true 时，将执行第一个分支（除非此操作码嵌套在未执行的分支中）。
//
// <expression> if [statements] [else [statements]] endif
//
// 请注意，与所有非条件操作码不同，即使它位于非执行分支上也会执行，因此可以保持正确的嵌套。
//
// Data stack transformation: [... bool] -> [...]
// Conditional stack transformation: [...] -> [... OpCondValue]
func opcodeIf(op *opcode, data []byte, vm *Engine) error {
	condVal := OpCondFalse
	if vm.isBranchExecuting() {
		ok, err := popIfBool(vm)
		if err != nil {
			return err
		}

		if ok {
			condVal = OpCondTrue
		}
	} else {
		condVal = OpCondSkip
	}
	vm.condStack = append(vm.condStack, condVal)
	return nil
}

// opcodeNotIf 将数据堆栈的顶部项目视为布尔值并将其删除。
//
// 根据布尔值是否为 true 以及该 if 是否位于执行分支上，将适当的条目添加到条件堆栈中，以便根据条件逻辑正确执行进一步的操作码。
// 当布尔值为 false 时，将执行第一个分支（除非此操作码嵌套在未执行的分支中）。
//
// <expression> notif [statements] [else [statements]] endif
//
// 请注意，与所有非条件操作码不同，即使它位于非执行分支上也会执行，因此可以保持正确的嵌套。
//
// Data stack transformation: [... bool] -> [...]
// Conditional stack transformation: [...] -> [... OpCondValue]
func opcodeNotIf(op *opcode, data []byte, vm *Engine) error {
	condVal := OpCondFalse
	if vm.isBranchExecuting() {
		ok, err := popIfBool(vm)
		if err != nil {
			return err
		}

		if !ok {
			condVal = OpCondTrue
		}
	} else {
		condVal = OpCondSkip
	}
	vm.condStack = append(vm.condStack, condVal)
	return nil
}

// opcodeElse 反转 if/else/endif 另一半的条件执行。
//
// 如果还没有匹配的 OP_IF，则返回错误。
//
// Conditional stack transformation: [... OpCondValue] -> [... !OpCondValue]
func opcodeElse(op *opcode, data []byte, vm *Engine) error {
	if len(vm.condStack) == 0 {
		str := fmt.Sprintf("encountered opcode %s with no matching "+
			"opcode to begin conditional execution", op.name)
		return scriptError(ErrUnbalancedConditional, str)
	}

	conditionalIdx := len(vm.condStack) - 1
	switch vm.condStack[conditionalIdx] {
	case OpCondTrue:
		vm.condStack[conditionalIdx] = OpCondFalse
	case OpCondFalse:
		vm.condStack[conditionalIdx] = OpCondTrue
	case OpCondSkip:
		// Value doesn't change in skip since it indicates this opcode
		// is nested in a non-executed branch.
	}
	return nil
}

// opcodeEndif 终止条件块，从条件执行堆栈中删除值。
//
// 如果还没有匹配的 OP_IF，则返回错误。
//
// Conditional stack transformation: [... OpCondValue] -> [...]
func opcodeEndif(op *opcode, data []byte, vm *Engine) error {
	if len(vm.condStack) == 0 {
		str := fmt.Sprintf("encountered opcode %s with no matching "+
			"opcode to begin conditional execution", op.name)
		return scriptError(ErrUnbalancedConditional, str)
	}

	vm.condStack = vm.condStack[:len(vm.condStack)-1]
	return nil
}

// AbstractVerify 将数据堆栈的顶部项目作为布尔值进行检查，并验证其计算结果是否为 true。
// 当堆栈上没有项目或该项目计算结果为 false 时，将返回错误。
// 在后一种情况下，验证由于顶部项目评估为 false 而失败，返回的错误将使用传递的错误代码。
func abstractVerify(op *opcode, vm *Engine, c ErrorCode) error {
	verified, err := vm.dstack.PopBool()
	if err != nil {
		return err
	}

	if !verified {
		str := fmt.Sprintf("%s failed", op.name)
		return scriptError(c, str)
	}
	return nil
}

// opcodeVerify 将数据堆栈的顶部项目作为布尔值进行检查，并验证其计算结果是否为 true。
// 如果不存在，则返回错误。
func opcodeVerify(op *opcode, data []byte, vm *Engine) error {
	return abstractVerify(op, vm, ErrVerify)
}

// opcodeReturn 返回适当的错误，因为从脚本提前返回始终是错误。
func opcodeReturn(op *opcode, data []byte, vm *Engine) error {
	return scriptError(ErrEarlyReturn, "script returned early")
}

// verifyLockTime 是一个用于验证锁定时间的辅助函数。
func verifyLockTime(txLockTime, threshold, lockTime int64) error {
	// The lockTimes in both the script and transaction must be of the same
	// type.
	if !((txLockTime < threshold && lockTime < threshold) ||
		(txLockTime >= threshold && lockTime >= threshold)) {
		str := fmt.Sprintf("mismatched locktime types -- tx locktime "+
			"%d, stack locktime %d", txLockTime, lockTime)
		return scriptError(ErrUnsatisfiedLockTime, str)
	}

	if lockTime > txLockTime {
		str := fmt.Sprintf("locktime requirement not satisfied -- "+
			"locktime is greater than the transaction locktime: "+
			"%d > %d", lockTime, txLockTime)
		return scriptError(ErrUnsatisfiedLockTime, str)
	}

	return nil
}

// opcodeCheckLockTimeVerify 将数据堆栈的顶部项与包含脚本签名的交易的 LockTime 字段进行比较，验证交易输出是否可花费。
// 如果未设置标志 ScriptVerifyCheckLockTimeVerify，则代码将继续执行，就像执行 OP_NOP2 一样。
func opcodeCheckLockTimeVerify(op *opcode, data []byte, vm *Engine) error {
	// If the ScriptVerifyCheckLockTimeVerify script flag is not set, treat
	// opcode as OP_NOP2 instead.
	if !vm.hasFlag(ScriptVerifyCheckLockTimeVerify) {
		if vm.hasFlag(ScriptDiscourageUpgradableNops) {
			return scriptError(ErrDiscourageUpgradableNOPs,
				"OP_NOP2 reserved for soft-fork upgrades")
		}
		return nil
	}

	// The current transaction locktime is a uint32 resulting in a maximum
	// locktime of 2^32-1 (the year 2106).  However, scriptNums are signed
	// and therefore a standard 4-byte scriptNum would only support up to a
	// maximum of 2^31-1 (the year 2038).  Thus, a 5-byte scriptNum is used
	// here since it will support up to 2^39-1 which allows dates beyond the
	// current locktime limit.
	//
	// PeekByteArray is used here instead of PeekInt because we do not want
	// to be limited to a 4-byte integer for reasons specified above.
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}
	lockTime, err := MakeScriptNum(so, vm.dstack.verifyMinimalData, 5)
	if err != nil {
		return err
	}

	// In the rare event that the argument needs to be < 0 due to some
	// arithmetic being done first, you can always use
	// 0 OP_MAX OP_CHECKLOCKTIMEVERIFY.
	if lockTime < 0 {
		str := fmt.Sprintf("negative lock time: %d", lockTime)
		return scriptError(ErrNegativeLockTime, str)
	}

	// The lock time field of a transaction is either a block height at
	// which the transaction is finalized or a timestamp depending on if the
	// value is before the LockTimeThreshold.  When it is under the
	// threshold it is a block height.
	err = verifyLockTime(int64(vm.tx.LockTime), LockTimeThreshold,
		int64(lockTime))
	if err != nil {
		return err
	}

	// The lock time feature can also be disabled, thereby bypassing
	// OP_CHECKLOCKTIMEVERIFY, if every transaction input has been finalized by
	// setting its sequence to the maximum value (wire.MaxTxInSequenceNum).  This
	// condition would result in the transaction being allowed into the blockchain
	// making the opcode ineffective.
	//
	// This condition is prevented by enforcing that the input being used by
	// the opcode is unlocked (its sequence number is less than the max
	// value).  This is sufficient to prove correctness without having to
	// check every input.
	//
	// NOTE: This implies that even if the transaction is not finalized due to
	// another input being unlocked, the opcode execution will still fail when the
	// input being used by the opcode is locked.
	if vm.tx.TxIn[vm.txIdx].Sequence == wire.MaxTxInSequenceNum {
		return scriptError(ErrUnsatisfiedLockTime,
			"transaction input is finalized")
	}

	return nil
}

// opcodeCheckSequenceVerify 将数据堆栈的顶部项目与包含脚本签名的交易的 LockTime 字段进行比较，以验证交易输出是否可花费。
// 如果未设置标志 ScriptVerifyCheckSequenceVerify，则代码将继续执行，就像执行 OP_NOP3 一样。
func opcodeCheckSequenceVerify(op *opcode, data []byte, vm *Engine) error {
	// If the ScriptVerifyCheckSequenceVerify script flag is not set, treat
	// opcode as OP_NOP3 instead.
	if !vm.hasFlag(ScriptVerifyCheckSequenceVerify) {
		if vm.hasFlag(ScriptDiscourageUpgradableNops) {
			return scriptError(ErrDiscourageUpgradableNOPs,
				"OP_NOP3 reserved for soft-fork upgrades")
		}
		return nil
	}

	// The current transaction sequence is a uint32 resulting in a maximum
	// sequence of 2^32-1.  However, scriptNums are signed and therefore a
	// standard 4-byte scriptNum would only support up to a maximum of
	// 2^31-1.  Thus, a 5-byte scriptNum is used here since it will support
	// up to 2^39-1 which allows sequences beyond the current sequence
	// limit.
	//
	// PeekByteArray is used here instead of PeekInt because we do not want
	// to be limited to a 4-byte integer for reasons specified above.
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}
	stackSequence, err := MakeScriptNum(so, vm.dstack.verifyMinimalData, 5)
	if err != nil {
		return err
	}

	// In the rare event that the argument needs to be < 0 due to some
	// arithmetic being done first, you can always use
	// 0 OP_MAX OP_CHECKSEQUENCEVERIFY.
	if stackSequence < 0 {
		str := fmt.Sprintf("negative sequence: %d", stackSequence)
		return scriptError(ErrNegativeLockTime, str)
	}

	sequence := int64(stackSequence)

	// To provide for future soft-fork extensibility, if the
	// operand has the disabled lock-time flag set,
	// CHECKSEQUENCEVERIFY behaves as a NOP.
	if sequence&int64(wire.SequenceLockTimeDisabled) != 0 {
		return nil
	}

	// Transaction version numbers not high enough to trigger CSV rules must
	// fail.
	if uint32(vm.tx.Version) < 2 {
		str := fmt.Sprintf("invalid transaction version: %d",
			vm.tx.Version)
		return scriptError(ErrUnsatisfiedLockTime, str)
	}

	// Sequence numbers with their most significant bit set are not
	// consensus constrained. Testing that the transaction's sequence
	// number does not have this bit set prevents using this property
	// to get around a CHECKSEQUENCEVERIFY check.
	txSequence := int64(vm.tx.TxIn[vm.txIdx].Sequence)
	if txSequence&int64(wire.SequenceLockTimeDisabled) != 0 {
		str := fmt.Sprintf("transaction sequence has sequence "+
			"locktime disabled bit set: 0x%x", txSequence)
		return scriptError(ErrUnsatisfiedLockTime, str)
	}

	// Mask off non-consensus bits before doing comparisons.
	lockTimeMask := int64(wire.SequenceLockTimeIsSeconds |
		wire.SequenceLockTimeMask)
	return verifyLockTime(txSequence&lockTimeMask,
		wire.SequenceLockTimeIsSeconds, sequence&lockTimeMask)
}

// opcodeToAltStack 从主数据堆栈中删除顶部项目并将其推送到备用数据堆栈上。
//
// Main data stack transformation: [... x1 x2 x3] -> [... x1 x2]
// Alt data stack transformation:  [... y1 y2 y3] -> [... y1 y2 y3 x3]
func opcodeToAltStack(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	vm.astack.PushByteArray(so)

	return nil
}

// opcodeFromAltStack 从备用数据堆栈中删除顶部项目并将其推送到主数据堆栈上。
//
// Main data stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 y3]
// Alt data stack transformation:  [... y1 y2 y3] -> [... y1 y2]
func opcodeFromAltStack(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.astack.PopByteArray()
	if err != nil {
		return err
	}
	vm.dstack.PushByteArray(so)

	return nil
}

// opcode2Drop 从数据堆栈中删除前 2 项。
//
// Stack transformation: [... x1 x2 x3] -> [... x1]
func opcode2Drop(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DropN(2)
}

// opcode2Dup 复制数据堆栈上的前 2 项。
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x2 x3]
func opcode2Dup(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DupN(2)
}

// opcode3Dup 复制数据堆栈上的前 3 个项目。
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x1 x2 x3]
func opcode3Dup(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DupN(3)
}

// opcode2Over 复制数据堆栈中前 2 个项目之前的 2 个项目。
//
// Stack transformation: [... x1 x2 x3 x4] -> [... x1 x2 x3 x4 x1 x2]
func opcode2Over(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.OverN(2)
}

// opcode2Rot 将数据堆栈上的前 6 项向左旋转两次。
//
// Stack transformation: [... x1 x2 x3 x4 x5 x6] -> [... x3 x4 x5 x6 x1 x2]
func opcode2Rot(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.RotN(2)
}

// opcode2Swap 将数据堆栈中前 2 个项目与其前面的 2 个项目交换。
//
// Stack transformation: [... x1 x2 x3 x4] -> [... x3 x4 x1 x2]
func opcode2Swap(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.SwapN(2)
}

// 如果 opcodeIfDup 不为零，则复制堆栈顶部的项目。
//
// Stack transformation (x1==0): [... x1] -> [... x1]
// Stack transformation (x1!=0): [... x1] -> [... x1 x1]
func opcodeIfDup(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}

	// Push copy of data iff it isn't zero
	if asBool(so) {
		vm.dstack.PushByteArray(so)
	}

	return nil
}

// opcodeDepth 在执行此操作码之前将数据堆栈的深度（编码为数字）推送到数据堆栈上。
//
// Stack transformation: [...] -> [... <num of items on the stack>]
// Example with 2 items: [x1 x2] -> [x1 x2 2]
// Example with 3 items: [x1 x2 x3] -> [x1 x2 x3 3]
func opcodeDepth(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushInt(scriptNum(vm.dstack.Depth()))
	return nil
}

// opcodeDrop 从数据堆栈中删除顶部项目。
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2]
func opcodeDrop(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DropN(1)
}

// opcodeDup 复制数据堆栈的顶部项目。
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x3]
func opcodeDup(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DupN(1)
}

// opcodeNip 删除数据堆栈顶部项目之前的项目。
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x3]
func opcodeNip(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.NipN(1)
}

// opcodeOver 复制数据堆栈顶部项目之前的项目。
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x2]
func opcodeOver(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.OverN(1)
}

// opcodePick 将数据堆栈上的顶部项目视为整数，并将堆栈上的项目数量复制回顶部。
//
// Stack transformation: [xn ... x2 x1 x0 n] -> [xn ... x2 x1 x0 xn]
// Example with n=1: [x2 x1 x0 1] -> [x2 x1 x0 x1]
// Example with n=2: [x2 x1 x0 2] -> [x2 x1 x0 x2]
func opcodePick(op *opcode, data []byte, vm *Engine) error {
	val, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	return vm.dstack.PickN(val.Int32())
}

// opcodeRoll 将数据堆栈顶部的项目视为整数，并将堆栈上相同数量项目的项目移回到顶部。
//
// Stack transformation: [xn ... x2 x1 x0 n] -> [... x2 x1 x0 xn]
// Example with n=1: [x2 x1 x0 1] -> [x2 x0 x1]
// Example with n=2: [x2 x1 x0 2] -> [x1 x0 x2]
func opcodeRoll(op *opcode, data []byte, vm *Engine) error {
	val, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	return vm.dstack.RollN(val.Int32())
}

// opcodeRot 将数据堆栈上的前 3 个项目向左旋转。
//
// Stack transformation: [... x1 x2 x3] -> [... x2 x3 x1]
func opcodeRot(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.RotN(1)
}

// opcodeSwap 交换堆栈顶部的两项。
//
// Stack transformation: [... x1 x2] -> [... x2 x1]
func opcodeSwap(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.SwapN(1)
}

// opcodeTuck 在倒数第二个项目之前插入数据堆栈顶部项目的副本。
//
// Stack transformation: [... x1 x2] -> [... x2 x1 x2]
func opcodeTuck(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.Tuck()
}

// opcodeSize 将数据栈顶项的大小压入数据栈。
//
// Stack transformation: [... x1] -> [... x1 len(x1)]
func opcodeSize(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}

	vm.dstack.PushInt(scriptNum(len(so)))
	return nil
}

// opcodeEqual 删除数据堆栈的前 2 项，将它们作为原始字节进行比较，并将结果（编码为布尔值）推回堆栈。
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeEqual(op *opcode, data []byte, vm *Engine) error {
	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushBool(bytes.Equal(a, b))
	return nil
}

// opcodeEqualVerify 是 opcodeEqual 和 opcodeVerify 的组合。
// 具体来说，它删除数据堆栈的顶部 2 项，比较它们，并将结果（编码为布尔值）推回堆栈。
// 然后，它检查数据堆栈顶部的项目作为布尔值，并验证其计算结果是否为 true。 如果不存在，则返回错误。
//
// Stack transformation: [... x1 x2] -> [... bool] -> [...]
func opcodeEqualVerify(op *opcode, data []byte, vm *Engine) error {
	err := opcodeEqual(op, data, vm)
	if err == nil {
		err = abstractVerify(op, vm, ErrEqualVerify)
	}
	return err
}

// opcode1Add 将数据堆栈的顶部项目视为整数，并将其替换为其增量值（加 1）。
//
// Stack transformation: [... x1 x2] -> [... x1 x2+1]
func opcode1Add(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(m + 1)
	return nil
}

// opcode1Sub 将数据堆栈的顶部项目视为整数，并用其递减值（负 1）替换它。
//
// Stack transformation: [... x1 x2] -> [... x1 x2-1]
func opcode1Sub(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	vm.dstack.PushInt(m - 1)

	return nil
}

// opcodeNegate 将数据堆栈的顶部项视为整数，并将其替换为它的负数。
//
// Stack transformation: [... x1 x2] -> [... x1 -x2]
func opcodeNegate(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(-m)
	return nil
}

// opcodeAbs 将数据堆栈的顶部项视为整数，并用其绝对值替换它。
//
// Stack transformation: [... x1 x2] -> [... x1 abs(x2)]
func opcodeAbs(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m < 0 {
		m = -m
	}
	vm.dstack.PushInt(m)
	return nil
}

// opcodeNot 将数据堆栈的顶部项视为整数，并将其替换为其“反转”值（0 变为 1，非零变为 0）。
//
// 注意：虽然将顶部项目视为布尔值并推动相反的值可能更有意义，这正是此操作码的真正意图，但不这样做非常重要，因为整数的解释方式与 布尔值和此操作码的共识规则规定该项目被解释为整数。
//
// Stack transformation (x2==0): [... x1 0] -> [... x1 1]
// Stack transformation (x2!=0): [... x1 1] -> [... x1 0]
// Stack transformation (x2!=0): [... x1 17] -> [... x1 0]
func opcodeNot(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m == 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcode0NotEqual 将数据堆栈的顶部项视为整数，如果为零则将其替换为 0，如果不为零则将其替换为 1。
//
// Stack transformation (x2==0): [... x1 0] -> [... x1 0]
// Stack transformation (x2!=0): [... x1 1] -> [... x1 1]
// Stack transformation (x2!=0): [... x1 17] -> [... x1 1]
func opcode0NotEqual(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m != 0 {
		m = 1
	}
	vm.dstack.PushInt(m)
	return nil
}

// opcodeAdd 将数据堆栈上的前两项视为整数，并用它们的总和替换它们。
//
// Stack transformation: [... x1 x2] -> [... x1+x2]
func opcodeAdd(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(v0 + v1)
	return nil
}

// opcodeSub 将数据堆栈上的前两项视为整数，并将它们替换为从倒数第二个条目减去顶部条目的结果。
//
// Stack transformation: [... x1 x2] -> [... x1-x2]
func opcodeSub(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(v1 - v0)
	return nil
}

// opcodeBoolAnd 将数据堆栈顶部的两项视为整数。 当两者都不为零时，用 1 代替，否则用 0 代替。
//
// Stack transformation (x1==0, x2==0): [... 0 0] -> [... 0]
// Stack transformation (x1!=0, x2==0): [... 5 0] -> [... 0]
// Stack transformation (x1==0, x2!=0): [... 0 7] -> [... 0]
// Stack transformation (x1!=0, x2!=0): [... 4 8] -> [... 1]
func opcodeBoolAnd(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != 0 && v1 != 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeBoolOr 将数据堆栈顶部的两项视为整数。 当其中任何一个不为零时，则用 1 代替，否则用 0 代替。
//
// Stack transformation (x1==0, x2==0): [... 0 0] -> [... 0]
// Stack transformation (x1!=0, x2==0): [... 5 0] -> [... 1]
// Stack transformation (x1==0, x2!=0): [... 0 7] -> [... 1]
// Stack transformation (x1!=0, x2!=0): [... 4 8] -> [... 1]
func opcodeBoolOr(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != 0 || v1 != 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeNumEqual 将数据堆栈顶部的两项视为整数。 当它们相等时，它们被替换为 1，否则被替换为 0。
//
// Stack transformation (x1==x2): [... 5 5] -> [... 1]
// Stack transformation (x1!=x2): [... 5 7] -> [... 0]
func opcodeNumEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 == v1 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeNumEqualVerify 是 opcodeNumEqual 和 opcodeVerify 的组合。
//
// 具体来说，将数据堆栈顶部的两项视为整数。 当它们相等时，它们被替换为 1，否则替换为 0。
// 然后，它检查数据堆栈顶部的项目作为布尔值，并验证其计算结果是否为 true。 如果不存在，则返回错误。
//
// Stack transformation: [... x1 x2] -> [... bool] -> [...]
func opcodeNumEqualVerify(op *opcode, data []byte, vm *Engine) error {
	err := opcodeNumEqual(op, data, vm)
	if err == nil {
		err = abstractVerify(op, vm, ErrNumEqualVerify)
	}
	return err
}

// opcodeNumNotEqual 将数据堆栈顶部的两项视为整数。
// 当它们不相等时，用 1 代替，否则用 0 代替。
//
// Stack transformation (x1==x2): [... 5 5] -> [... 0]
// Stack transformation (x1!=x2): [... 5 7] -> [... 1]
func opcodeNumNotEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != v1 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeLessThan 将数据堆栈上的前两项视为整数。 当倒数第二个项目小于顶部项目时，它们被替换为 1，否则被替换为 0。
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeLessThan(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 < v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeGreaterThan 将数据堆栈上的前两项视为整数。
// 当倒数第二个项目大于顶部项目时，它们被替换为 1，否则替换为 0。
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeGreaterThan(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 > v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcodeLessThanOrEqual 将数据堆栈上的前两项视为整数。
// 当倒数第二个项目小于或等于顶部项目时，它们被替换为 1，否则替换为 0。
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeLessThanOrEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 <= v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcodeGreaterThanOrEqual 将数据堆栈上的前两项视为整数。
// 当倒数第二个项目大于或等于顶部项目时，它们被替换为 1，否则替换为 0。
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeGreaterThanOrEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 >= v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeMin 将数据堆栈上的前两项视为整数，并用两者中的最小值替换它们。
//
// Stack transformation: [... x1 x2] -> [... min(x1, x2)]
func opcodeMin(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 < v0 {
		vm.dstack.PushInt(v1)
	} else {
		vm.dstack.PushInt(v0)
	}

	return nil
}

// opcodeMax 将数据堆栈上的前两项视为整数，并用两者中的最大值替换它们。
//
// Stack transformation: [... x1 x2] -> [... max(x1, x2)]
func opcodeMax(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 > v0 {
		vm.dstack.PushInt(v1)
	} else {
		vm.dstack.PushInt(v0)
	}

	return nil
}

// opcodeWithin 将数据堆栈上的前 3 项视为整数。 当要测试的值在指定范围内（包括左侧）时，它们将替换为 1，否则替换为 0。
//
// 顶部项目是最大值，第二顶部项目是最小值，第三顶部项目是要测试的值。
//
// Stack transformation: [... x1 min max] -> [... bool]
func opcodeWithin(op *opcode, data []byte, vm *Engine) error {
	maxVal, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	minVal, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	x, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if x >= minVal && x < maxVal {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// calcHash 通过 buf 计算 hasher 的哈希值。
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// opcodeRipemd160 将数据堆栈的顶部项视为原始字节，并将其替换为ripemd160(data)。
//
// Stack transformation: [... x1] -> [... ripemd160(x1)]
func opcodeRipemd160(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushByteArray(calcHash(buf, ripemd160.New()))
	return nil
}

// opcodeSha1 将数据堆栈的顶部项目视为原始字节，并将其替换为 sha1(data)。
//
// Stack transformation: [... x1] -> [... sha1(x1)]
func opcodeSha1(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha1.Sum(buf)
	vm.dstack.PushByteArray(hash[:])
	return nil
}

// opcodeSha256 将数据堆栈的顶部项视为原始字节，并将其替换为 sha256(data)。
//
// Stack transformation: [... x1] -> [... sha256(x1)]
func opcodeSha256(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(buf)
	vm.dstack.PushByteArray(hash[:])
	return nil
}

// opcodeHash160 将数据堆栈的顶部项视为原始字节，并将其替换为ripemd160(sha256(data))。
//
// Stack transformation: [... x1] -> [... ripemd160(sha256(x1))]
func opcodeHash160(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(buf)
	vm.dstack.PushByteArray(calcHash(hash[:], ripemd160.New()))
	return nil
}

// opcodeHash256 将数据堆栈的顶部项视为原始字节，并将其替换为 sha256(sha256(data))。
//
// Stack transformation: [... x1] -> [... sha256(sha256(x1))]
func opcodeHash256(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushByteArray(chainhash.DoubleHashB(buf))
	return nil
}

// opcodeCodeSeparator 将当前脚本偏移量存储为最近看到的 OP_CODESEPARATOR，在签名检查期间使用。
//
// 该操作码不会更改数据堆栈的内容。
func opcodeCodeSeparator(op *opcode, data []byte, vm *Engine) error {
	vm.lastCodeSep = int(vm.tokenizer.ByteIndex())

	if vm.taprootCtx != nil {
		vm.taprootCtx.codeSepPos = uint32(vm.tokenizer.OpcodePosition())
	}

	return nil
}

// opcodeCheckSig 将堆栈上的前 2 项视为公钥和签名，并将它们替换为指示签名是否已成功验证的布尔值。
//
// 验证签名的过程需要以与交易签名者相同的方式计算签名哈希。
// 它涉及基于哈希类型字节（这是签名的最后一个字节）的交易的哈希部分以及从最近的 OP_CODESEPARATOR （或脚本的开头，如果没有）开始到结束的脚本部分 脚本的（删除任何其他 OP_CODESEPARATOR）。
// 一旦计算出“脚本哈希”，就会使用标准加密方法根据提供的公钥检查签名。
//
// Stack transformation: [... signature pubkey] -> [... bool]
func opcodeCheckSig(op *opcode, data []byte, vm *Engine) error {
	pkBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	fullSigBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// The signature actually needs needs to be longer than this, but at
	// least 1 byte is needed for the hash type below.  The full length is
	// checked depending on the script flags and upon parsing the signature.
	//
	// This only applies if tapscript verification isn't active, as this
	// check is done within the sighash itself.
	if vm.taprootCtx == nil && len(fullSigBytes) < 1 {
		vm.dstack.PushBool(false)
		return nil
	}

	var sigVerifier signatureVerifier
	switch {
	// If no witness program is active, then we're verifying under the
	// base consensus rules.
	case vm.witnessProgram == nil:
		sigVerifier, err = newBaseSigVerifier(
			pkBytes, fullSigBytes, vm,
		)
		if err != nil {
			var scriptErr Error
			if errors.As(err, &scriptErr) {
				return err
			}

			vm.dstack.PushBool(false)
			return nil
		}

	// If the base segwit version is active, then we'll create the verifier
	// that factors in those new consensus rules.
	case vm.isWitnessVersionActive(BaseSegwitWitnessVersion):
		sigVerifier, err = newBaseSegwitSigVerifier(
			pkBytes, fullSigBytes, vm,
		)
		if err != nil {
			var scriptErr Error
			if errors.As(err, &scriptErr) {
				return err
			}

			vm.dstack.PushBool(false)
			return nil
		}

	// Otherwise, this is routine tapscript execution.
	case vm.taprootCtx != nil:
		// Account for changes in the sig ops budget after this
		// execution, but only for non-empty signatures.
		if len(fullSigBytes) > 0 {
			if err := vm.taprootCtx.tallysigOp(); err != nil {
				return err
			}
		}

		// Empty public keys immediately cause execution to fail.
		if len(pkBytes) == 0 {
			return scriptError(ErrTaprootPubkeyIsEmpty, "")
		}

		// If this is tapscript execution, and the signature was
		// actually an empty vector, then we push on an empty vector
		// and continue execution from there, but only if the pubkey
		// isn't empty.
		if len(fullSigBytes) == 0 {
			vm.dstack.PushByteArray([]byte{})
			return nil
		}

		// If the constructor fails immediately, then it's because
		// the public key size is zero, so we'll fail all script
		// execution.
		sigVerifier, err = newBaseTapscriptSigVerifier(
			pkBytes, fullSigBytes, vm,
		)
		if err != nil {
			return err
		}

	default:
		// We skip segwit v1 in isolation here, as the v1 rules aren't
		// used in script execution (for sig verification) and are only
		// part of the top-level key-spend verification which we
		// already skipped.
		//
		// In other words, this path shouldn't ever be reached
		//
		// TODO(roasbeef): return an error?
	}

	valid := sigVerifier.Verify()

	switch {
	// For tapscript, and prior execution with null fail active, if the
	// signature is invalid, then this MUST be an empty signature.
	case !valid && vm.taprootCtx != nil && len(fullSigBytes) != 0:
		fallthrough
	case !valid && vm.hasFlag(ScriptVerifyNullFail) && len(fullSigBytes) > 0:
		str := "signature not empty on failed checksig"
		return scriptError(ErrNullFail, str)
	}

	vm.dstack.PushBool(valid)
	return nil
}

// opcodeCheckSigVerify 是 opcodeCheckSig 和 opcodeVerify 的组合。
// 调用 opcodeCheckSig 函数，然后调用 opcodeVerify。 有关更多详细信息，请参阅每个操作码的文档。
//
// Stack transformation: [... signature pubkey] -> [... bool] -> [...]
func opcodeCheckSigVerify(op *opcode, data []byte, vm *Engine) error {
	err := opcodeCheckSig(op, data, vm)
	if err == nil {
		err = abstractVerify(op, vm, ErrCheckSigVerify)
	}
	return err
}

// opcodeCheckSigAdd 实现了 BIP 342 中定义的 OP_CHECKSIGADD 操作。这是 OP_CHECKMULTISIGVERIFY 和 OP_CHECKMULTISIG 的替代品，可以更好地进行批量签名验证，以及跨输入签名聚合的可能未来。
//
// 操作码采用公钥、整数 (N) 和签名，如果签名是空向量，则返回 N，否则返回 n+1。
//
// Stack transformation: [... pubkey n signature] -> [... n | n+1 ] -> [...]
func opcodeCheckSigAdd(op *opcode, data []byte, vm *Engine) error {
	// This op code can only be used if tapsript execution is active.
	// Before the soft fork, this opcode was marked as an invalid reserved
	// op code.
	if vm.taprootCtx == nil {
		str := fmt.Sprintf("attempt to execute invalid opcode %s", op.name)
		return scriptError(ErrReservedOpcode, str)
	}

	// Pop the signature, integer n, and public key off the stack.
	pubKeyBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	accumulatorInt, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	sigBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Only non-empty signatures count towards the total tapscript sig op
	// limit.
	if len(sigBytes) != 0 {
		// Account for changes in the sig ops budget after this execution.
		if err := vm.taprootCtx.tallysigOp(); err != nil {
			return err
		}
	}

	// Empty public keys immediately cause execution to fail.
	if len(pubKeyBytes) == 0 {
		return scriptError(ErrTaprootPubkeyIsEmpty, "")
	}

	// If the signature is empty, then we'll just push the value N back
	// onto the stack and continue from here.
	if len(sigBytes) == 0 {
		vm.dstack.PushInt(accumulatorInt)
		return nil
	}

	// Otherwise, we'll attempt to validate the signature as normal.
	//
	// If the constructor fails immediately, then it's because the public
	// key size is zero, so we'll fail all script execution.
	sigVerifier, err := newBaseTapscriptSigVerifier(
		pubKeyBytes, sigBytes, vm,
	)
	if err != nil {
		return err
	}

	valid := sigVerifier.Verify()

	// If the signature is invalid, this we fail execution, as it should
	// have been an empty signature.
	if !valid {
		str := "signature not empty on failed checksig"
		return scriptError(ErrNullFail, str)
	}

	// Otherwise, we increment the accumulatorInt by one, and push that
	// back onto the stack.
	vm.dstack.PushInt(accumulatorInt + 1)

	return nil
}

// parsedSigInfo 包含一个原始签名及其解析形式以及一个表示是否已解析的标志。 它用于防止在验证多重签名时多次解析相同的签名。
type parsedSigInfo struct {
	signature       []byte
	parsedSignature *ecdsa.Signature
	parsed          bool
}

// opcodeCheckMultiSig 将堆栈顶部的项目视为整数个公钥，后面跟着那么多条目作为代表公钥的原始数据，然后是整数个签名，最后跟着那么多条目作为代表签名的原始数据。
//
// 由于原始中本聪客户端实现中的错误，共识规则还需要一个额外的虚拟参数，尽管它没有被使用。 虚拟值应该是 OP_0，尽管共识规则并不要求这样做。 当设置 ScriptStrictMultiSig 标志时，它必须是 OP_0。
//
// 所有上述堆栈项均替换为布尔值，指示是否成功验证了所需数量的签名。
//
// 有关验证每个签名的过程的更多详细信息，请参阅 opcodeCheckSigVerify 文档。
//
// 堆栈转换：
// [... dummy [sig ...] numsigs [pubkey ...] numpubkeys] -> [... bool]
func opcodeCheckMultiSig(op *opcode, data []byte, vm *Engine) error {
	// If we're doing tapscript execution, then this op code is disabled.
	if vm.taprootCtx != nil {
		str := fmt.Sprintf("OP_CHECKMULTISIG and " +
			"OP_CHECKMULTISIGVERIFY are disabled during " +
			"tapscript execution")
		return scriptError(ErrTapscriptCheckMultisig, str)
	}

	numKeys, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	numPubKeys := int(numKeys.Int32())
	if numPubKeys < 0 {
		str := fmt.Sprintf("number of pubkeys %d is negative",
			numPubKeys)
		return scriptError(ErrInvalidPubKeyCount, str)
	}
	if numPubKeys > MaxPubKeysPerMultiSig {
		str := fmt.Sprintf("too many pubkeys: %d > %d",
			numPubKeys, MaxPubKeysPerMultiSig)
		return scriptError(ErrInvalidPubKeyCount, str)
	}
	vm.numOps += numPubKeys
	if vm.numOps > MaxOpsPerScript {
		str := fmt.Sprintf("exceeded max operation limit of %d",
			MaxOpsPerScript)
		return scriptError(ErrTooManyOperations, str)
	}

	pubKeys := make([][]byte, 0, numPubKeys)
	for i := 0; i < numPubKeys; i++ {
		pubKey, err := vm.dstack.PopByteArray()
		if err != nil {
			return err
		}
		pubKeys = append(pubKeys, pubKey)
	}

	numSigs, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	numSignatures := int(numSigs.Int32())
	if numSignatures < 0 {
		str := fmt.Sprintf("number of signatures %d is negative",
			numSignatures)
		return scriptError(ErrInvalidSignatureCount, str)

	}
	if numSignatures > numPubKeys {
		str := fmt.Sprintf("more signatures than pubkeys: %d > %d",
			numSignatures, numPubKeys)
		return scriptError(ErrInvalidSignatureCount, str)
	}

	signatures := make([]*parsedSigInfo, 0, numSignatures)
	for i := 0; i < numSignatures; i++ {
		signature, err := vm.dstack.PopByteArray()
		if err != nil {
			return err
		}
		sigInfo := &parsedSigInfo{signature: signature}
		signatures = append(signatures, sigInfo)
	}

	// A bug in the original Satoshi client implementation means one more
	// stack value than should be used must be popped.  Unfortunately, this
	// buggy behavior is now part of the consensus and a hard fork would be
	// required to fix it.
	dummy, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Since the dummy argument is otherwise not checked, it could be any
	// value which unfortunately provides a source of malleability.  Thus,
	// there is a script flag to force an error when the value is NOT 0.
	if vm.hasFlag(ScriptStrictMultiSig) && len(dummy) != 0 {
		str := fmt.Sprintf("multisig dummy argument has length %d "+
			"instead of 0", len(dummy))
		return scriptError(ErrSigNullDummy, str)
	}

	// Get script starting from the most recent OP_CODESEPARATOR.
	script := vm.subScript()

	// Remove the signature in pre version 0 segwit scripts since there is
	// no way for a signature to sign itself.
	if !vm.isWitnessVersionActive(0) {
		for _, sigInfo := range signatures {
			script = removeOpcodeByData(script, sigInfo.signature)
		}
	}

	success := true
	numPubKeys++
	pubKeyIdx := -1
	signatureIdx := 0
	for numSignatures > 0 {
		// When there are more signatures than public keys remaining,
		// there is no way to succeed since too many signatures are
		// invalid, so exit early.
		pubKeyIdx++
		numPubKeys--
		if numSignatures > numPubKeys {
			success = false
			break
		}

		sigInfo := signatures[signatureIdx]
		pubKey := pubKeys[pubKeyIdx]

		// The order of the signature and public key evaluation is
		// important here since it can be distinguished by an
		// OP_CHECKMULTISIG NOT when the strict encoding flag is set.

		rawSig := sigInfo.signature
		if len(rawSig) == 0 {
			// Skip to the next pubkey if signature is empty.
			continue
		}

		// Split the signature into hash type and signature components.
		hashType := SigHashType(rawSig[len(rawSig)-1])
		signature := rawSig[:len(rawSig)-1]

		// Only parse and check the signature encoding once.
		var parsedSig *ecdsa.Signature
		if !sigInfo.parsed {
			if err := vm.checkHashTypeEncoding(hashType); err != nil {
				return err
			}
			if err := vm.checkSignatureEncoding(signature); err != nil {
				return err
			}

			// Parse the signature.
			var err error
			if vm.hasFlag(ScriptVerifyStrictEncoding) ||
				vm.hasFlag(ScriptVerifyDERSignatures) {

				parsedSig, err = ecdsa.ParseDERSignature(signature)
			} else {
				parsedSig, err = ecdsa.ParseSignature(signature)
			}
			sigInfo.parsed = true
			if err != nil {
				continue
			}
			sigInfo.parsedSignature = parsedSig
		} else {
			// Skip to the next pubkey if the signature is invalid.
			if sigInfo.parsedSignature == nil {
				continue
			}

			// Use the already parsed signature.
			parsedSig = sigInfo.parsedSignature
		}

		if err := vm.checkPubKeyEncoding(pubKey); err != nil {
			return err
		}

		// Parse the pubkey.
		parsedPubKey, err := btcec.ParsePubKey(pubKey)
		if err != nil {
			continue
		}

		// Generate the signature hash based on the signature hash type.
		var hash []byte
		if vm.isWitnessVersionActive(0) {
			var sigHashes *TxSigHashes
			if vm.hashCache != nil {
				sigHashes = vm.hashCache
			} else {
				sigHashes = NewTxSigHashes(
					&vm.tx, vm.prevOutFetcher,
				)
			}

			hash, err = calcWitnessSignatureHashRaw(script, sigHashes, hashType,
				&vm.tx, vm.txIdx, vm.inputAmount)
			if err != nil {
				return err
			}
		} else {
			hash = calcSignatureHash(script, hashType, &vm.tx, vm.txIdx)
		}

		var valid bool
		if vm.sigCache != nil {
			var sigHash chainhash.Hash
			copy(sigHash[:], hash)

			valid = vm.sigCache.Exists(sigHash, signature, pubKey)
			if !valid && parsedSig.Verify(hash, parsedPubKey) {
				vm.sigCache.Add(sigHash, signature, pubKey)
				valid = true
			}
		} else {
			valid = parsedSig.Verify(hash, parsedPubKey)
		}

		if valid {
			// PubKey verified, move on to the next signature.
			signatureIdx++
			numSignatures--
		}
	}

	if !success && vm.hasFlag(ScriptVerifyNullFail) {
		for _, sig := range signatures {
			if len(sig.signature) > 0 {
				str := "not all signatures empty on failed checkmultisig"
				return scriptError(ErrNullFail, str)
			}
		}
	}

	vm.dstack.PushBool(success)
	return nil
}

// opcodeCheckMultiSigVerify 是 opcodeCheckMultiSig 和 opcodeVerify 的组合。 opcodeCheckMultiSig 被调用，然后是 opcodeVerify。
// 有关更多详细信息，请参阅每个操作码的文档。
//
// Stack transformation:
// [... dummy [sig ...] numsigs [pubkey ...] numpubkeys] -> [... bool] -> [...]
func opcodeCheckMultiSigVerify(op *opcode, data []byte, vm *Engine) error {
	err := opcodeCheckMultiSig(op, data, vm)
	if err == nil {
		err = abstractVerify(op, vm, ErrCheckMultiSigVerify)
	}
	return err
}

// OpcodeByName 是一个映射，可用于通过人类可读的名称（OP_CHECKMULTISIG、OP_CHECKSIG 等）查找操作码。
var OpcodeByName = make(map[string]byte)

func init() {
	// 使用操作码数组的内容将操作码名称初始化为值映射。
	// 还要添加“OP_FALSE”、“OP_TRUE”和“OP_NOP2”条目，因为它们分别是“OP_0”、“OP_1”和“OP_CHECKLOCKTIMEVERIFY”的别名。
	for _, op := range opcodeArray {
		OpcodeByName[op.name] = op.value
	}
	OpcodeByName["OP_FALSE"] = OP_FALSE
	OpcodeByName["OP_TRUE"] = OP_TRUE
	OpcodeByName["OP_NOP2"] = OP_CHECKLOCKTIMEVERIFY
	OpcodeByName["OP_NOP3"] = OP_CHECKSEQUENCEVERIFY
}
