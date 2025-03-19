# Keycloak JS test suite

This directory contains the test suite for Keycloak JS, which is based on [Playwright](https://playwright.dev/). It contains a suite of integration tests that embed the adapter in various scenarios and tests it against a Keycloak server running in the background.

## Setup

Run the following command to install the [Playwright browsers](https://playwright.dev/docs/browsers) and required system dependencies:

```sh
npx playwright install
```

It might be that this command fails due to missing system dependencies, in that case add the `--with-deps` flag:

```sh
npx playwright install --with-deps
```

### Setup on Linux distributions unsupported by Playwright

Playwright doesn't support some Linux-based distributions, if you are on Linux and the installation steps above did not work for you, follow the steps below, otherwise, skip to [running the tests](#running-the-tests).

In order to run the tests on unsupported distributions you can use Distrobox to run an Ubuntu 22.04 image on top of your host system, which is supported by Playwright.

#### 1. Install `distrobox` and `podman` packages

First, install both [Distrobox](https://distrobox.it/#installation) and [Podman](https://podman.io/docs/installation). Then, create home directory for your Distrobox environment (this helps avoid conflicts with your host system's home directory):

```sh
mkdir ~/distrobox
```

#### 2. Create a container environment to run tests

Create a container in your host (for more information see the [documentation](https://distrobox.it/)):

```sh
distrobox create \
  --name pw --image ubuntu:22.04 \
  --home ~/distrobox  \
  --root \
  --additional-packages "podman libgtk2.0-0 libgtk-3-0 libgbm-dev libnotify-dev libnss3 libxss1 libasound2 libxtst6 xauth xvfb" \
  --unshare-all \
  --absolutely-disable-root-password-i-am-really-positively-sure
```

Now enter the created Distrobox environment using:

```sh
distrobox enter --root pw
```

#### 3. Install Node.js

Whilst inside of the Distrobox environment, install Node.js by following the instructions from the [Node.js download page](https://nodejs.org/en/download). Using the latest LTS version is recommended.


It should now be possible to install the Playwright browsers by running the following command from the project root:

```sh
npx playwright install --with-deps
```

## Running the tests

Make sure you are in the `test` directory. To run the tests headlessly you can run the following command:

```sh
npm test
```

It is also possible to run the tests in [various other modes](https://playwright.dev/docs/running-tests), for example, to debug the tests `--debug` can be passed:

```sh
npm test -- --debug
```

## Speeding up testing

By default, the tests will run against a Keycloak server that is running the latest version. This server is started by Playwright using Podman by running the following command:

```sh
podman run -p 8080:8080 -p 9000:9000 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -e KC_HEALTH_ENABLED=true --pull=newer quay.io/keycloak/keycloak:latest start-dev
```

Alternatively, if you want to run the Keycloak server straight from the distribution (or your local development instance), without using Podman you can run it as follows:

```sh
KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin KC_HEALTH_ENABLED=true ./bin/kc.sh start-dev
```

Every time the tests run the Keycloak server will also be restarted, which can slow down development. You can instead opt to keep a Keycloak server running in the background, and re-use this server. To do so, remove the `gracefulShutdown` section from the Playwright configuration (`playwright.config.ts`):

```diff
{
-  gracefulShutdown: {
-    // Podman requires a termination signal to stop.
-    signal: 'SIGTERM',
-    timeout: 5000
-  }
},
```
