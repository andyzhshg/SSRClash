FROM ubuntu:18.04

RUN apt-get update && apt-get install -y python3-pip git
RUN pip3 install flask_restful && pip3 install requests

WORKDIR /root
RUN git clone https://github.com/andyzhshg/SSRClash.git

WORKDIR /root/SSRClash

CMD [ "python3", "SSR_Clash_API.py" ]
