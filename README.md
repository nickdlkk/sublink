# sublink for python3
[![电报群组][telegram-image]][tg-url]
![python][python-image]
![vue2][vue-image]
[![作者][author-image]][author-url]

[telegram-image]:https://img.shields.io/badge/%E7%94%B5%E6%8A%A5%E7%BE%A4%E7%BB%84-TG-red?label=%E7%94%B5%E6%8A%A5%E7%BE%A4%E7%BB%84
[tg-url]:https://t.me/+u6gLWF0yP5NiZWQ1
[python-image]:https://img.shields.io/badge/python3.8.2-blue
[vue-image]:https://img.shields.io/badge/vue2-rand
[author-image]:https://img.shields.io/badge/%E4%BD%9C%E8%80%85-TG-8A2BE2
[author-url]:https://t.me/toutie_1


<p align="center">
   <img width="45%" style="border:solid 1px #DCEBFB" src="readme/1.png" >
   <img width="45%" style="border:solid 1px #DCEBFB" src="readme/2.png">
</p>

#### USDT (TRC20):TQ1bheWesAxByGrMztrZFhRFrUZDbJkdse

# 2.9-1更新说明：

修复surpe hy2协议
新增删除登录记录命令
新增query中cert证书自定义

# 功能说明：

节点转换成订阅，并且能够一直存储

方便多订阅管理，个人搭建使用

解决安全问题预防被偷节点,集成前后端

目前支持v2ray|clash|surge

v2ray格式通用的软件已测有下:v2rayn 小火箭等，还有一些没用过不知名

默认账户密码都是admin，请记得修改否则容易泄漏

# 安装说明：

## 拉取或者更新docker镜像

如果你有旧版本拉取前可以先停止和删除容器再删除镜像

docker rm -f sublink

docker images

docker rmi 这里填写IMAGEID

然后拉取镜像输入，默认拉取就是最新版本

 ```docker pull jaaksi/sublink```

## 启动docker

<details>
<summary>挂载到当前目录下(方式一)</summary>

进入到你的目录比如你可以创建一个sublink目录然后输入

```
docker run --name sublink -p 8000:5000 \
-v $PWD/db:/app/app/db \
-e PORT=5000 \
-d jaaksi/sublink
```

</details>

<details>
<summary>挂载到数据卷(方式二)</summary>

```
docker run --name sublink -p 8000:5000 \
-v sublink_data:/app/app/db \
-e PORT=5000 \
-d jaaksi/sublink
```
查看数据存放目录docker volume inspect sublink_data
</details>

<details>
<summary>docker-compose(方式三)</summary>

下载docker-compose.yml,然后启动

```docker-compose up -d```

</details>

| 参数 | 说明          |
|--------------|--------------|
| p          | 公网端口:容器端口    |
| name       | docker名字  |
| v        | 挂载目录 |
| e        | 端口环境变量  |
| d        | 后台方式启动  |


# 假如你忘记了账号或者密码

初始化为admin，确保你的容器在运行的时候终端执行以下命令：

    docker exec -it sublink bash -c "python init_user_pw.py; exit"

# 清空登录记录

确保你的容器在运行的时候终端执行以下命令：
docker exec -it sublink bash -c "python init_login_log.py; exit"

## Stargazers over time

[![Stargazers over time](https://starchart.cc/jaaksii/sublink.svg?variant=adaptive)](https://starchart.cc/jaaksii/sublink)

# TODO

1. [ ] 订阅记录
2. [ ] 剩余流量
