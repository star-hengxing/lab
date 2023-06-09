# 基于 Detours 的 hook

`src/hook/test.cpp`是一个无限弹窗的程序，我们通过注入 dll 然后 hook 程序使其正常退出。

## 方法

Detours 库的`DetourCreateProcessWithDllEx`系列函数，可以注入一个或多个 dll，利用`CreateProcess`接口创建程序的时候，可以设置参数`CREATE_SUSPENDED`使进程挂起，然后修改内存里的 PE 二进制（改 Import Directory Table），使其加载我们的 dll。

## 应用

- 游戏转区
- 监控程序行为（火绒）

## 参考

- [Microsoft Research Detours Package Overview](https://github.com/microsoft/Detours/wiki)
- [Windows Ring3层注入——注入相关知识（零）](https://blog.csdn.net/qq_38493448/article/details/104005406)
- [YY-Guard——有效缓解DLL劫持攻击](https://github.com/Chuyu-Team/YY-Guard)
