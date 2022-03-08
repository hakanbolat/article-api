FROM php:8.0-fpm-alpine

LABEL maintainer="Hakan BOLAT <blt-hkn@hotmail.com>"

ADD php.ini /usr/local/etc/php/php.ini

ARG DC_USER_ID
ARG DC_GROUP_ID

RUN set -ex \
    && apk --no-cache add curl oniguruma oniguruma-dev postgresql-dev \
    && docker-php-ext-install pdo_pgsql \
    && docker-php-ext-install pgsql

RUN apk --no-cache add shadow \
    && usermod -u $DC_USER_ID www-data \
    && groupmod -g $DC_GROUP_ID www-data

USER "$DC_USER_ID:$DC_GROUP_ID"

WORKDIR /web
