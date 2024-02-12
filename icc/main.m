clear; clc;

% Implementation of Error Correction Code ICC 
% http://elaineshi.com/docs/por.pdf
% Practical Dynamic Proofs of Retrievability, CCS' 13
% Author: Tung Le
% Email: tungle@vt.edu 

% Number of data blocks
n = 2^6;
% Level
l = 4;
% Time
t = 1;

% FFT Vandermonde matrix
F_l  = fft_transform_matrix(n, l);

% Diagonal matrix 
D_lt = fft_diag_matrix(n, l, t);

% Generator matrix
G    = [F_l, D_lt * F_l];

% Original data
data = randi([1 100], 1, 2^l);
disp('Data: ');
disp(data);

% Hierarchical log at level l
H_l = data * G;

% Suppose that 2^l positions have been corrupted 
% And other 2^l positions are good
sub_H_l = H_l;
sub_G_l = G;

H_size  = length(sub_H_l); 

for i = 1:2^l
    % Choose a random column as corrupted column to be removed
    j = randi(H_size);
    
    % Remove column j in Hierarchical Log H
    sub_H_l(:,j) = [];
    
    % Remove column j in Generator G
    sub_G_l(:, j) = [];
    
    % Decrease size due to the removed column
    H_size = H_size - 1;
end

% Recover data by using only 2^l arbitrary columns
recovered_data = int32(sub_G_l'\sub_H_l')';

% Display recovered data
disp('Recovered Data: ');
disp(recovered_data);
