
FROM ubuntu

COPY ./init /

CMD ["/init"]

EXPOSE 10000
