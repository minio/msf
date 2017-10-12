# Federator Contribution Guide [![Slack](https://slack.minio.io/slack?type=svg)](https://slack.minio.io) [![Go Report Card](https://goreportcard.com/badge/minio/mfs)](https://goreportcard.com/report/minio/mfs)

``Federator`` community welcomes your contribution. To make the process as seamless as possible, we recommend you read this contribution guide.

## Development Workflow

Start by forking the Federator GitHub repository, make changes in a branch and then send a pull request. We encourage pull requests to discuss code changes. Here are the steps in details:

### Setup your Federator Github Repository
Fork [Federator upstream](https://github.com/minio/mfs/fork) source repository to your own personal repository. Copy the URL of your Federator fork (you will need it for the `git clone` command below).

```sh
$ mkdir -p $GOPATH/src/github.com/minio
$ cd $GOPATH/src/github.com/minio
$ git clone <paste saved URL for personal forked minio repo>
$ cd minio
```

### Set up git remote as ``upstream``
```sh
$ cd $GOPATH/src/github.com/minio/mfs
$ git remote add upstream https://github.com/minio/mfs
$ git fetch upstream
$ git merge upstream/master
...
```

### Create your feature branch
Before making code changes, make sure you create a separate branch for these changes

```
$ git checkout -b my-new-feature
```

### Test Federator server changes
After your code changes, make sure

- To add test cases for the new code. If you have questions about how to do it, please ask on our [Slack](slack.minio.io) channel.
- To run `make verifiers`
- To squash your commits into a single commit. `git rebase -i`. It's okay to force update your pull request.
- To run `go test -race ./...` and `go build` completes.

### Commit changes
After verification, commit your changes. This is a [great post](https://chris.beams.io/posts/git-commit/) on how to write useful commit messages

```
$ git commit -am 'Add some feature'
```

### Push to the branch
Push your locally committed changes to the remote origin (your fork)
```
$ git push origin my-new-feature
```

### Create a Pull Request
Pull requests can be created via GitHub. Refer to [this document](https://help.github.com/articles/creating-a-pull-request/) for detailed steps on how to create a pull request. After a Pull Request gets peer reviewed and approved, it will be merged.

## FAQs
### How does ``Federator`` manages dependencies?
``Federator`` manages its dependencies using [govendor](https://github.com/kardianos/govendor). To add a dependency
- Run `go get foo/bar`
- Edit your code to import foo/bar
- Run `govendor add foo/bar` from top-level directory

To remove a dependency
- Edit your code to not import foo/bar
- Run `govendor remove foo/bar` from top-level directory

### What are the coding guidelines for Federator?
``Federator`` is fully conformant with Golang style. Refer: [Effective Go](https://github.com/golang/go/wiki/CodeReviewComments) article from Golang project. If you observe offending code, please feel free to send a pull request or ping us on [Slack](slack.minio.io).
