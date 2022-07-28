# MemoryDumpIl2Cpp
### 这是一个 基于Unity引擎的 dump Il2Cpp 的工具， 可以生成 dump.cs il2cpp.h script.json 。 并且不需要global-metadata.dat 。但是需要其他一些信息来辅助分析。

### 效果图如下所示 基本与PC Il2Cppdumper 生成的一致；
![image](https://github.com/IIIImmmyyy/MemoryDumpIl2Cpp/blob/main/ida.png)

## 如何使用
这里将使用frida 和Riru 来举例说明

### frida 
#### 找到在IDA 中以下的3个地址
```
let s_GlobalMetadataHeader=0XC1D130
let s_Il2CppMetadataRegistration=0XC1D100
let s_Il2CppCodeRegistration= 0XC1D0F8
let il2cppHandle
function  findIl2cppHandler (){
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
}


```






