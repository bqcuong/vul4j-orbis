FROM bqcuongas/java:latest

# install required softwares
RUN apt update \
    && apt install -y wget curl vim zsh patch \
    unzip bzip2 xz-utils \
    git \
    python3 python3-pip \
    maven

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true

COPY ./ /vul4j/

WORKDIR /vul4j

RUN python3 setup.py install

# set env
ENV BENCHMARK_PATH /vul4j
ENV DATASET_PATH /vul4j/dataset/vul4j_dataset.csv
ENV REPRODUCTION_DIR /vul4j/reproduction
ENV PROJECT_REPOS_ROOT_PATH /vul4j/project_repos
