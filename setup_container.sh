# This script intends to install podman and setup the container used by AirBugCatcher.
# This script should be executed on the host, not in the container. After this script
# finishes, please head into the container to continue the setup.
sudo apt update
sudo apt install podman
sudo podman pull docker.io/megarbelini/5ghoul:release-5g-x86_64
sudo podman run --privileged \
    --network=host \
    --user=root \
    -v /run/udev:/run/udev:ro \
    -v /dev:/dev \
    --device-cgroup-rule='c 188:* rmw' \
    --systemd=always \
    --entrypoint="/sbin/init" \
    --restart=always \
    --name="airbugcatcher_eval" \
    -dt docker.io/megarbelini/5ghoul:release-5g-x86_64
echo 'The container to evaluate AirBugCatcher has been started with name "airbugcatcher_eval".'
echo 'Please enter the container to continue installing AirBugCatcher.'
