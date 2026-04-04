
`sudo docker build -t pqc-reporter .`
`sudo docker run --rm -v "/home/sujith/Desktop/websites/eagle_campus/backend:/src" pqc-reporter`

```bash
sudo docker run --rm -u $(id -u):$(id -g) -v "/home/sujith/Desktop/websites/eagle_campus/backend:/data" pqc-reporter \
  --input-dir /data/pqc-reports \
  --cbom /data/final-cbom.json \
  --output-dir /data/pqc-reports/report \
  --project-name "Eagle Campus Backend"
```


`docker build -t devsecops-reporter -f Dockerfile.reporter .`
`docker run --rm -v "$(pwd):/src" pqc-reporter`



> Still no permission to edit pdf