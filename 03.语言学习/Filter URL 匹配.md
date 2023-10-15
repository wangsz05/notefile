## Fileter过滤器

过滤器判断逻辑该返回很重要，如果没有该返回方法，则出错了也会执行`filterChain.doFilter(servletRequest, servletResponse);` 进入到下一个过滤器，相当于绕过了该过滤器

![image-20220921193605943](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220921193605943.png)



## URL 匹配

![image-20220920235453381](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220920235453381.png)