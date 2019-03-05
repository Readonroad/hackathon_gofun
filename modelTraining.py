import tensorflow as tf
from tensorflow.examples.tutorials.mnist import input_data
import os
import pandas as pd
import numpy as np

vdatapathx = r'flowtype/randomx.csv'
vdatapathy = r'flowtype/randomy.csv'
datax = pd.read_csv(vdatapathx, dtype=np.float32, header=None)
datay = pd.read_csv(vdatapathy, dtype=np.float32, header=None)

print(datax.shape)
print(datay.shape)

def weight_variable(shape):
    initial = tf.truncated_normal(shape, stddev=0.1)   #获取截断随机数
    return tf.Variable(initial)
def bias_variable(shape):
    initial = tf.constant(0.1, shape=shape)
    return tf.Variable(initial)

con1_number = 8
w_con1_desc={'wsize':[4,16,1, con1_number], 'strides':[1,1,4,1], 'padding':'SAME'}
pool1 = {'ksize':[1,1,2,1], 'strides':[1,1,1,1], 'padding':'SAME'}

x = tf.placeholder(tf.float32,[None, 4*256*1])
y_ = tf.placeholder(tf.float32, [None, 4])

x_input = tf.reshape(x, [-1,4,256,1])   #-1表示默认值
w_conv1 = weight_variable(w_con1_desc['wsize'])
b_conv1 = bias_variable([con1_number])

h1 = tf.nn.conv2d(x_input, w_conv1, strides=w_con1_desc['strides'], padding=w_con1_desc['padding'])
h_conv1 = tf.nn.relu(tf.nn.bias_add(h1, b_conv1))
h_pool1 = tf.nn.max_pool(h_conv1, ksize=pool1['ksize'], strides=pool1['strides'], padding=pool1['padding'])

#输出为(-1, 4, 64, 8)
con2_number = 8
w_con2_desc={'wsize':[4,8,8, con2_number], 'strides':[1,1,2,1], 'padding':'SAME'}
pool2 = {'ksize':[1,1,2,1], 'strides':[1,1,1,1], 'padding':'SAME'}
w_conv2 = weight_variable(w_con2_desc['wsize'])
b_conv2 = bias_variable([con2_number])

h2 = tf.nn.conv2d(h_pool1, w_conv2, strides=w_con2_desc['strides'], padding=w_con2_desc['padding'])
h_conv2 = tf.nn.relu(tf.nn.bias_add(h2, b_conv2))
h_pool2 = tf.nn.max_pool(h_conv2, ksize=pool2['ksize'], strides=pool2['strides'], padding=pool2['padding'])
#输出为(5, 4, 32, 8)

W_fc1 = weight_variable([4*32*8, 1024])
b_fc1 = bias_variable([1024])

h_pool2_flat = tf.reshape(h_pool2, [-1, 4*32*8])
h_fc1 = tf.nn.relu(tf.matmul(h_pool2_flat,W_fc1) + b_fc1)

keep_prob = tf.placeholder(tf.float32)
h_fc1_dropout = tf.nn.dropout(h_fc1, keep_prob)

W_fc2 = weight_variable([1024,4])
b_fc2 = bias_variable([4])
h_fc2 = tf.matmul(h_fc1_dropout, W_fc2) + b_fc2
y_conv = h_fc2

cross_entropy = tf.reduce_mean(tf.nn.softmax_cross_entropy_with_logits(labels=y_, logits=y_conv))
train_step = tf.train.AdamOptimizer(1e-4).minimize(cross_entropy)
accuracy = tf.reduce_mean(tf.cast(tf.equal(tf.argmax(y_, 1), tf.argmax(y_conv, 1)), tf.float32))

def getData(data, i, number):
    start_index = (i*number)%30000
    return data.iloc[start_index:(start_index+number), 0:1024]

# init_op = tf.global_variables_initializer()
# sess = tf.Session()
# sess.run(init_op)

# out = sess.run(cross_entropy, feed_dict={x:getData(datax, 0, 5), y_:getData(datay, 0, 5), keep_prob:1.0})
# print(out)
with tf.Session() as sess:
    tf.global_variables_initializer().run()
    for i in range(5000):
        # batch = mnist.train.next_batch(50)
        batchx = getData(datax, i, 200)
        batchy = getData(datay, i, 200)
        if i % 100 == 0:
            train_accuracy = accuracy.eval(feed_dict = {x: batchx,
                                                       y_: batchy,
                                                       keep_prob: 1.})
            print('setp {},the train accuracy: {}'.format(i, train_accuracy))

        train_step.run(feed_dict = {x: batchx, y_: batchy, keep_prob: 0.5})
    # test_accuracy = accuracy.eval(feed_dict = {x: getData(datax, 0, 500), y_: getData(datax, 0, 500), keep_prob: 1.})
    # print('the test accuracy :{}'.format(test_accuracy))
