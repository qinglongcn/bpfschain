// 通常包含包的文档说明，描述 txscript 包的目的和总体用途

/*
txscript 包实现了比特币交易脚本语言。

比特币使用的脚本语言的完整描述可以在 https://en.bitcoin.it/wiki/Script 找到。
以下仅作为快速概述，提供有关如何使用该包的信息。

该包提供了解析和执行比特币交易脚本的数据结构和函数。

# 脚本概述

比特币交易脚本是用基于堆栈、类似 FORTH 的语言编写的。

比特币脚本语言由许多操作码组成，这些操作码分为几个类别，例如将数据推入堆栈和从堆栈弹出数据、执行基本和按位算术、条件分支、比较哈希值以及检查加密签名。
脚本是从左到右处理的，并且故意不提供循环。

在撰写本文时，绝大多数比特币脚本都有几种标准形式，其中包括提供公钥的支出者和证明支出者拥有相关私钥的签名。
该信息用于证明消费者有权执行交易。

使用脚本语言的好处之一是可以更加灵活地指定使用比特币必须满足的条件。

# 错误

该包返回的错误类型为 txscript.Error。
这允许调用者通过检查断言的 txscript.Error 类型的 ErrorCode 字段以编程方式确定特定错误，同时仍然提供带有上下文信息的丰富错误消息。
还提供了一个名为 IsErrorCode 的便捷函数，允许调用者轻松检查特定的错误代码。
有关完整列表，请参阅包文档中的 ErrorCode。
*/
package txscript

/**

bench_test.go			包含基准测试代码，用于评估与交易脚本相关的不同函数和方法的性能。
consensus.go			包含与比特币共识规则相关的脚本验证逻辑。
doc.go					通常包含包的文档说明，描述 txscript 包的目的和总体用途。
engine_test.go			包含脚本执行引擎的单元测试代码。
engine.go				包含脚本执行引擎的核心代码，负责处理脚本的解析和执行。
engine_debug_test.go	包含脚本执行引擎的调试测试代码。
error_test.go			包含测试 error.go 中定义的错误类型的代码。
error.go				定义了脚本处理过程中可能遇到的错误类型。
example_test.go			提供了 txscript 包使用示例的测试代码。
hashcache_test.go		包含测试哈希缓存功能的代码。
hashcache.go			实现了一个哈希缓存，用于优化交易签名验证过程。
logrus.go					定义了日志记录的相关功能，可能用于调试和跟踪脚本执行。
opcode_test.go			包含测试脚本操作码的代码。
opcode.go				包含比特币脚本语言中所有操作码的实现。
pkscript_test.go		包含测试公钥脚本处理功能的代码。
pkscript.go				包含处理公钥脚本（即输出脚本）的函数和方法。
reference_test.go		可能包含一些参考测试，用于确保脚本处理与比特币核心实现保持一致。
script_test.go			包含测试脚本处理功能的代码。
script.go				包含处理脚本字节码的基本函数和方法。
scriptbuilder_test.go	包含测试脚本构建器的代码。
scriptbuilder.go		包含一个构建器，用于以编程方式构建脚本。
scriptnum_test.go		包含测试脚本数字处理的代码。
scriptnum.go			实现了脚本数字的处理，这是比特币脚本语言的一个特性。
sigcache_test.go		包含测试签名缓存功能的代码。
sigcache.go				实现了一个签名缓存，用于提高交易验证的效率。
sighash.go				包含计算交易签名哈希的函数，这是签名验证过程的一部分。
sign_test.go			包含测试交易签名功能的代码。
sign.go					包含创建交易签名的函数。
sigvalidate.go			可能包含签名验证相关的函数和方法。
stack_test.go			包含测试数据栈功能的代码。
stack.go				实现了一个数据栈，用于脚本执行过程中的数据存储。
standard_test.go		包含测试标准交易处理功能的代码。
standard.go				包含识别和处理标准交易类型的函数。
taproot_test.go			包含测试 Taproot 相关脚本处理的代码。
taproot.go				包含处理 Taproot 相关脚本逻辑的代码，Taproot 是比特币协议的一个较新的升级。
tokenizer_test.go		包含测试脚本令牌化功能的代码。
tokenizer.go			包含脚本令牌化的逻辑，用于将脚本分解为可执行的操作码和数据。

*/
