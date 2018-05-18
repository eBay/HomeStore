## Building

### Requirements
* Docker >= v18.03.ce

### Environment

```
~/dev $ docker pull ecr.vip.ebayc3.com/sds/sds_develop
~/dev $ alias sds_dev='docker run --rm -it --privileged -v $(pwd):/tmp/source  -P ecr.vip.ebayc3.com/sds/sds_develop'
~/dev $ git clone git@github.corp.ebay.com:SDS/homestore
~/dev $ sds_dev
root@27a278223024:/tmp/build# conan install ../source/homestore
root@27a278223024:/tmp/build# conan build ../source/homestore
```

### Suggestions

Preserve the alias in the commands above to your profile!
