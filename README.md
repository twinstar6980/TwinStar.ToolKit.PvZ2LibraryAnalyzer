# TwinStar ToolKit - PvZ-2 Library Analyzer

**这是一个废弃的项目（最后功能更新于2022-05-12），代码质量低，并且预计不会再维护，即使可能存在 BUG 。**

开发本项目的目的是作为 `TwinStar ToolKit` 的补充，它可以帮助使用者对 libPvZ2.so 进行分析。

## 使用

本项目需要作为逆向分析软件 IDA 的 Python 插件使用。

## 功能

* RtObject Parser
	
	`RtObject` 是 PvZ-2 中所有 `RTON object` 的基类，不同的 `RTON object` 通过 `objclass` 字段对应到特定的 `RtObject` 派生类。
	
	本项目可分析国际版 `6.2 ~ 9.9` 版本的 `ARMv7` 架构的 `libPVZ2.so` 文件，从中解析出 `RtObject` 类及其所有派生类的反序列化信息，得到该类的继承关系与成员组成。
	
	所得的序列号信息表代表了 RTON object 的格式规范，对与 PvZ-2 RTON/JSON 修改会有很多帮助。
