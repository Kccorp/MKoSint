FROM python:3.11

WORKDIR /app

RUN apt update -y && apt install -y git && \
git clone https://github.com/Kccorp/MKoSint.git 

#WORKDIR /app/MKoSint

VOLUME /app/results

RUN python MKoSint/install.py 

ENTRYPOINT ["python", "MKoSint/main.py"]

CMD ["-h"]
