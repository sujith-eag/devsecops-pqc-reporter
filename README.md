
`sudo docker build -t pqc-reporter .`
`sudo docker run --rm -v "/home/sujith/Desktop/websites/eagle_campus/backend:/src" pqc-reporter`


`docker build -t devsecops-reporter -f Dockerfile.reporter .`
`docker run --rm -v "$(pwd):/src" pqc-reporter`

