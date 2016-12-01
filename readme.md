
### 客户端验证模块

### 编译

main.cc 中包含的 protocol.h 需要修改路径为当前目录


### 简单例子

```cpp

// 接口介绍
// 引入头文件 networklic.h

int main(int argc ,char *argv[])
{
  bool actived = false;
  uint32_t runtime = 100;
  const char *log = NULL;
  // 初始化模块
  // 函数自动定时 checkout
  if(argc != -1)
    lic_init( "127.0.0.1",10080, 46);
  do{
    // 检测许可证是否获取
    actived = lic_license());
    std::cout << actived ? "f" : "t" << std::endl;
    // 输出 debug 日志信息
    log = log_stream();
    std::cout << log << std::endl;
    free_log_stream(log);
    Sleep(1000);
  }
  while( --runtime );

  // 激活状态下应该 checkin 返回授权
  if(actived)
    lic_check_in();
  else if(argc != 1){
    // 重设端口号尝试获取授权
    reset_endpoint("192.168.0.11", 10081);
    return main(-1, argv);
  }

  return 0;
}

```
