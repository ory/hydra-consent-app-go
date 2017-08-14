# hydra-consent-app-go

[![Build Status](https://travis-ci.org/ory/hydra-consent-app-go.svg?branch=master)](https://travis-ci.org/ory/hydra-consent-app-go)

This is a simple consent app for Hydra written in Go. It uses the Hydra SDK. To run the example, first install Hydra
and this project:

```
go get -u -d github.com/ory/hydra-consent-app-go
go get -u github.com/Masterminds/glide
cd $GOPATH/src/github.com/ory/hydra-consent-app-go
glide install
```

Next open a shell and run:

```sh
export FORCE_ROOT_CLIENT_CREDENTIALS=demo:demo
export CONSENT_URL=http://localhost:4445/consent
hydra host --dangerous-force-http
```

In another console, run

```
hydra-consent-app-go
```

or alternatively, if you're in the project's directory:

```
go run main.go
```

Then, open the browser:

```
open http://localhost:4445/
```

Now follow the steps described in the browser. If you encounter an error, use the browser's back button to get back
to the last screen.

Keep in mind that you will not be able to refresh the callback url, as the authorize code is
valid only once. Also, this application needs to run on port 4445 in order for the demo to work. Usually the consent
endpoint won't perform the authorize code, but for the sake of the demo we added that too.

Make sure that you stop the docker-compose demo of the Hydra main repository, otherwise ports 4445 and 4444 are unassignable.
