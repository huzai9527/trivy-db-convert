# trivy-db-convert
## 目标

- 将 trivy.db 非关系型数据库格式数据转化为 mysql 、sqlite 关系型数据库格式【目前已实现】
- 将mysql、sqlite 的关系型数据库格式转化为 trivy.db 的KV类型数据【正在构建】

## 演示

```shell
 go build -o trivy-db-convert main.go 
 ./trivy-db-convert trivy2sql -d 'root:asdqwe123.@tcp(10.211.55.3:3306)/vuln' -s mysql -t ./
```
<img width="982" alt="image" src="https://user-images.githubusercontent.com/33509974/182587977-82f66913-3230-4ad9-b443-6bd8dbe3a987.png">

- 参数意义
  - `-d` 表示链接数据库使用的dsn，遵循 `xorm` 的格式要求即可
  - `-s` 表示数据库类型，目前支持 `mysql/sqlite`
  - `-t` 表示 `db/trivy.db` 所在的文件夹
  - `-c` 表示是否清除原有的表

## 表结构

<img width="969" alt="image" src="https://user-images.githubusercontent.com/33509974/182587939-5ad1f5f5-907e-42d2-b4d6-f923789cbf27.png">
<img width="954" alt="image" src="https://user-images.githubusercontent.com/33509974/182588023-c131002e-a6eb-4662-9661-2df491d6fcbc.png">


## 实际效果

- 数据库会出现如下的两张表

<img width="1005" alt="image" src="https://user-images.githubusercontent.com/33509974/182588068-b876e433-4268-49b9-b262-4dae926dbb9b.png">
- vulnerablity

<img width="962" alt="image" src="https://user-images.githubusercontent.com/33509974/182588133-902e5bcf-a8b6-4f22-8eda-25de4a3f4c52.png">
<img width="702" alt="image" src="https://user-images.githubusercontent.com/33509974/182588348-31ed1772-cefc-4161-ac22-674f07b2a6d8.png">  


- vulnrablity_advisory

<img width="960" alt="image" src="https://user-images.githubusercontent.com/33509974/182588516-e42479ad-e80e-4cff-ad0c-4fddc079fedc.png">
<img width="854" alt="image" src="https://user-images.githubusercontent.com/33509974/182588622-52a391a4-c5c1-42c4-ba53-b3fb731899ed.png">
  
