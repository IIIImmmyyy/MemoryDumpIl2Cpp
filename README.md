# MemoryDumpIl2Cpp
[中文点这里](https://github.com/IIIImmmyyy/MemoryDumpIl2Cpp/blob/main/README_CN.md)

this is dump unity Il2Cpp  CS Struct and IDA Script without global-metadata.dat  in Runtime. but need others to analyse it;

as shown in the figure  
![image](https://github.com/IIIImmmyyy/MemoryDumpIl2Cpp/blob/main/ida.png)

## How to Use
### need  one root android phone.
#### push so to /system/lib64
#### create config to same path such as
![image](https://github.com/IIIImmmyyy/MemoryDumpIl2Cpp/blob/main/so.png)

#### config 
```
{
"outDir":"/data/data/com.imy.i2lcpp", //outPath
"forceVer":0 //force unity ver
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
####  use frida to inject

####  find this in IDA
```
let s_GlobalMetadataHeader=0XC1D130
let s_Il2CppMetadataRegistration=0XC1D100
let s_Il2CppCodeRegistration= 0XC1D0F8
```
#### get il2cppso handle
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
#### load so
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
#### if you need loginfo  filter "Imy" in Logcat 
```
IDA Script create Done!
generating il2cpp.h
il2cpp.h create done! 
```
#### when dump success this info will appear , and it will be  create dump.cs il2cpp.h script.json stringLiteral.json in /data/data/pkgName/files/

## this so only support 64 and unity version in 2018.3.0f2-2018.4.36f1, other version not support
## if you want more version  Contact
```
email: 295238641@qq.com
```





