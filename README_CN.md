# MemoryDumpIl2Cpp
### 这是一个 基于Unity引擎的 内存dump Il2Cpp 的工具， 可以生成 dump.cs il2cpp.h script.json 。 并且不需要global-metadata.dat 以及解密SO 。但是需要其他一些信息来辅助分析。（仅支持Android）

### 效果图如下所示 基本与PC Il2Cppdumper 生成的一致；
![image](https://github.com/IIIImmmyyy/MemoryDumpIl2Cpp/blob/main/ida.png)

## 如何使用
### 需要root手机 如果非root手机 需要自己完成注入，这里以root手机为例

#### push so 到 /system/lib64/   
#### 创建一个配置文件，与so同路径， 并且以so的命名拼接.config 结尾
![image](https://github.com/IIIImmmyyy/MemoryDumpIl2Cpp/blob/main/so.png)
#### 配置文件以下所示
```
{
"outDir":"/data/data/com.imy.i2lcpp", //输出路径
"forceVer":0 //是否强制以某个版本来分析 提示版本异常 需要指定unity引擎对应metadata 的版本号
}


// UnityVersion Compatible list
// 5.3.0f4     | 5.3.0f4 - 5.3.1f1         | v16
// 5.3.2f1     | 5.3.2f1                   | v19
// 5.3.3f1     | 5.3.3f1 - 5.3.4f1         | v20
// 5.3.5f1     | 5.3.5f1                   | v21
// 5.3.6f1     | 5.3.6f1                   | v21
// 5.3.7f1     | 5.3.7f1 - 5.3.8f2         | v21
// 5.4.0f3     | 5.4.0f3                   | v21
// 5.4.1f1     | 5.4.1f1 - 5.4.3f1         | v21
// 5.4.4f1     | 5.4.4f1 - 5.4.6f3         | v21
// 5.5.0f3     | 5.5.0f3                   | v22
// 5.5.1f1     | 5.5.1f1 - 5.5.6f1         | v22
// 5.6.0f3     | 5.6.0f3 - 5.6.7f1         | v23
// 2017.1.0f3  | 2017.1.0f3 - 2017.1.2f1   | v24
// 2017.1.3f1  | 2017.1.3f1 - 2017.1.5f1   | v24
// 2017.2.0f3  | 2017.2.0f3                | v24
// 2017.2.1f1  | 2017.2.1f1 - 2017.4.40f1  | v24
// 2018.1.0f2  | 2018.1.0f2 - 2018.1.9f2   | v24
// 2018.2.0f2  | 2018.2.0f2 - 2018.2.21f1  | v24
// 2018.3.0f2  | 2018.3.0f2 - 2018.3.7f1   | v24.1
// 2018.3.8f1  | 2018.3.8f1 - 2018.4.36f1  | v24.1
// 2019.1.0f2  | 2019.1.0f2 - 2019.2.21f1  | v24.2
// 2019.3.0f6  | 2019.3.0f6 - 2019.3.6f1   | v24.2
// 2019.3.7f1  | 2019.3.7f1 - 2019.4.14f1  | v24.3
// 2019.4.15f1 | 2019.4.15f1 - 2019.4.20f1 | v24.4
// 2019.4.21f1 | 2019.4.21f1 - 2019.4.29f1 | v24.5
// 2020.1.0f1  | 2020.1.0f1 - 2020.1.10f1  | v24.3
// 2020.1.11f1 | 2020.1.11f1 - 2020.1.17f1 | v24.4
// 2020.2.0f1  | 2020.2.0f1 - 2020.2.3f1   | v27
// 2020.2.4f1  | 2020.2.4f1 - 2020.3.15f2  | v27.1
// 2021.1.0f1  | 2021.1.0f1 - 2021.1.16f1  | v27.2
```

#### 这里将使用frida 来完成注入的演示

#### 找到在IDA 中以下的3个地址
```
let s_GlobalMetadataHeader=0XC1D130
let s_Il2CppMetadataRegistration=0XC1D100
let s_Il2CppCodeRegistration= 0XC1D0F8
```
#### 获得il2cppso的句柄`
```
let dlopen = Module.findExportByName(null,"dlopen");
    if (dlopen != null) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                let path = args[0].readCString();
                if (path.indexOf(soName) !== -1) {
                    this.hook = true;
                }
              
            },
            onLeave: function (retval) {
                if (this.hook) {
                        il2cppHandler = new NativePointer(s);

                }
            }
        })
    }
```

#### 加载SO 并且运行
```
let module = Process.findModuleByName('libil2cpp.so');
let il2CppGlobalMetadataHeader = module.base.add(s_GlobalMetadataHeader).readPointer();
let il2cppMetadataRegistration = module.base.add(s_Il2CppMetadataRegistration).readPointer();
let il2cppCodeRegistrantion = module.base.add(s_Il2CppCodeRegistration).readPointer();

let dumperSo = Module.load("/system/lib64/libdumper.so");
let dumpstartAddr = dumperSo.findExportByName("_ZN8CSDumper5startEPvS0_S0_S0_"); 
let start_fun = new NativeFunction(dumpstartAddr,"void",['pointer','pointer','pointer','pointer']);
start_fun(il2CppGlobalMetadataHeader,il2cppMetadataRegistration,il2CppCodeRegistration,il2cppHandler);

```
#### 需要观察log可在LogCat中过滤 Imy 并且提示以下信息则成功
```
IDA Script create Done!
generating il2cpp.h
il2cpp.h create done! 
```
#### 并且在对应/data/data/pkgName/files/ 下生成 dump.cs il2cpp.h script.json stringLiteral.json 则成功


## 注意！ 开放的so 仅支持64位并且 引擎 版本为2018.3.0f2-2018.4.36f1 其他版本dump均会出错

## 32位 及更多Unity版本(魔改unity) 支持 请联系
```
QQ:295238641
邮箱: 295238641@qq.com
```








