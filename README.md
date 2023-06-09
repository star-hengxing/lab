# 计算机科学实验室

# 开始

## 依赖

- 构建系统：[xmake](https://xmake.io/#/zh-cn/guide/installation)
- 编译工具链：[Visual Studio](https://visualstudio.microsoft.com/)（不需要 vs 则下载[Microsoft C++ 生成工具](https://visualstudio.microsoft.com/visual-cpp-build-tools/)）

> Visual Studio 最好安装在默认目录

## 构建

- `xmake f -h`查看所有选项，然后选择你想要的实验

```sh
xmake config --hook=y
xmake --yes
```

构建完成后，可以选择使用`xmake run target`运行程序，或者直接到 build 目录直接打开程序

# 实验

- [基于 Detours 的 hook](src/hook/README.md)
